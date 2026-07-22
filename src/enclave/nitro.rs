//! Native-only AWS Nitro attestation and KMS boundary primitives.
//!
//! This module deliberately stops at an offline, transport-neutral boundary.
//! It parses the AWS Nitro CBOR/COSE shape, verifies the COSE P-384 signature,
//! enforces exact local policy, and requires an injected certificate trust
//! decision before returning a narrowly scoped offline verification receipt.
//! It does not contact NSM, vsock, AWS KMS, a network, or an AWS root store,
//! and it is not exported to the WASM surface. The receipt is structural
//! offline evidence only: durable replay consumption is not completed,
//! production provider verification remains unavailable, and no value-bearing
//! authorization is created.

use ciborium::{de, ser, value::Value};
use der::{
    asn1::{ObjectIdentifier, SequenceRef, UintRef},
    Decode,
};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, io::Cursor};
use x509_cert::{ext::pkix::BasicConstraints, spki::SubjectPublicKeyInfoOwned, Certificate};

/// AWS Nitro's COSE_Sign1 protected-header algorithm identifier for ES384.
pub const NITRO_COSE_ES384_ALGORITHM: i64 = -35;
/// COSE tag identifying a tagged COSE_Sign1 structure.
pub const NITRO_COSE_SIGN1_TAG: u64 = 18;
/// Maximum transport size accepted by this offline boundary.
pub const MAX_NITRO_ATTESTATION_BYTES: usize = 262_144;
/// Maximum embedded attestation payload size from the AWS Nitro shape.
pub const MAX_NITRO_PAYLOAD_BYTES: usize = 16_384;
/// Maximum certificate size accepted by the AWS Nitro shape.
pub const MAX_NITRO_CERTIFICATE_BYTES: usize = 1_024;
/// Maximum number of certificates retained in a bounded CA bundle.
pub const MAX_NITRO_CA_BUNDLE_CERTIFICATES: usize = 16;
/// Maximum optional user-data, nonce, or public-key field size.
pub const MAX_NITRO_OPTIONAL_FIELD_BYTES: usize = 1_024;
/// SHA-384 PCR width required by this explicit SHA384-only profile.
pub const NITRO_SHA384_PCR_BYTES: usize = 48;
/// Maximum bounded ciphertext returned for a KMS recipient response.
pub const MAX_NITRO_CIPHERTEXT_FOR_RECIPIENT_BYTES: usize = 6_144;
/// Minimum RSA recipient modulus size accepted by this offline profile.
pub const MIN_NITRO_RSA_MODULUS_BITS: usize = 2_048;
/// Version of the deterministic release binding carried in `user_data`.
pub const NITRO_RELEASE_BINDING_VERSION: u16 = 1;

const MAX_MODULE_ID_BYTES: usize = 256;
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_AGE_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_NITRO_CBOR_DEPTH: usize = 64;
const RELEASE_BINDING_DOMAIN: &[u8] = b"CONXIAN-NITRO-KMS-RELEASE-BINDING/v1\0";
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Secret-safe errors produced by the Nitro boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum NitroError {
    #[error("Nitro input exceeds the bounded transport limit")]
    InputTooLarge,
    #[error("Nitro CBOR is malformed")]
    CborMalformed,
    #[error("Nitro CBOR contains trailing data")]
    CborTrailingData,
    #[error("Nitro CBOR contains a duplicate map key")]
    CborDuplicateMapKey,
    #[error("Nitro CBOR contains an unsupported value type")]
    CborUnsupportedType,
    #[error("Nitro CBOR exceeds the bounded nesting depth")]
    CborNestingTooDeep,
    #[error("COSE_Sign1 has an invalid shape")]
    CoseInvalidShape,
    #[error("COSE_Sign1 payload is missing")]
    CoseMissingPayload,
    #[error("COSE_Sign1 protected ES384 algorithm is required")]
    CoseUnsupportedAlgorithm,
    #[error("COSE_Sign1 protected headers are required")]
    CoseProtectedHeaderRequired,
    #[error("COSE_Sign1 unprotected headers must be empty")]
    CoseUnprotectedHeaderNotEmpty,
    #[error("COSE_Sign1 signature has an invalid length")]
    CoseSignatureLength,
    #[error("Nitro payload contains an unknown field")]
    PayloadUnknownField,
    #[error("Nitro payload contains a duplicate field")]
    PayloadDuplicateField,
    #[error("Nitro payload is missing a required field")]
    PayloadMissingField,
    #[error("Nitro payload field has the wrong type")]
    PayloadFieldType,
    #[error("Nitro payload field has an invalid length")]
    PayloadFieldLength,
    #[error("Nitro module identifier is invalid")]
    InvalidModuleId,
    #[error("Nitro module identifier does not match policy")]
    ModuleIdMismatch,
    #[error("Nitro timestamp is invalid")]
    InvalidTimestamp,
    #[error("Nitro digest must be SHA384")]
    InvalidDigest,
    #[error("Nitro PCR index is unsupported")]
    InvalidPcrIndex,
    #[error("Nitro PCR value is invalid")]
    InvalidPcrValue,
    #[error("Nitro leaf certificate is invalid")]
    InvalidCertificate,
    #[error("Nitro CA bundle is invalid")]
    InvalidCaBundle,
    #[error("Nitro recipient public key is invalid")]
    InvalidRecipientPublicKey,
    #[error("Nitro COSE signature verification failed")]
    SignatureInvalid,
    #[error("Nitro certificate trust-boundary verification is required")]
    TrustBoundaryRequired,
    #[error("Nitro certificate trust-boundary verification rejected the document")]
    TrustBoundaryRejected,
    #[error("Nitro attestation timestamp is expired")]
    TimestampExpired,
    #[error("Nitro attestation timestamp is too far in the future")]
    TimestampFuture,
    #[error("Nitro freshness policy is invalid")]
    FreshnessPolicyInvalid,
    #[error("Nitro nonce is missing")]
    MissingNonce,
    #[error("Nitro nonce does not match the expected challenge")]
    NonceMismatch,
    #[error("Nitro release binding is missing")]
    MissingReleaseBinding,
    #[error("Nitro release binding is malformed")]
    ReleaseBindingMalformed,
    #[error("Nitro release binding does not match the expected request")]
    ReleaseBindingMismatch,
    #[error("Nitro release binding is expired")]
    ReleaseBindingExpired,
    #[error("Nitro PCR policy must require at least one measurement")]
    PcrPolicyEmpty,
    #[error("Nitro PCR policy is invalid")]
    PcrPolicyInvalid,
    #[error("Nitro PCR policy requires a missing measurement")]
    MissingRequiredPcr,
    #[error("Nitro PCR measurement does not match policy")]
    PcrMismatch,
    #[error("Nitro PCR policy rejects an all-zero required measurement")]
    AllZeroRequiredPcr,
    #[error("Nitro attestation public key is missing")]
    MissingPublicKey,
    #[error("Nitro attestation public key does not match the expected recipient")]
    PublicKeyMismatch,
    #[error("KMS recipient algorithm must be RSAES_OAEP_SHA_256")]
    RecipientAlgorithmUnsupported,
    #[error("KMS recipient attestation bytes are required")]
    RecipientAttestationMissing,
    #[error("KMS CiphertextForRecipient is missing or out of bounds")]
    RecipientCiphertextInvalid,
    #[error("KMS plaintext response is forbidden for a recipient request")]
    RecipientPlaintextRejected,
}

/// The semantic meaning of the six standard Nitro measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NitroPcrSemantic {
    /// Enclave image file measurement.
    EnclaveImage,
    /// Linux kernel and bootstrap measurement.
    KernelAndBootstrap,
    /// Enclave application measurement.
    Application,
    /// Parent-instance IAM role measurement.
    ParentIamRole,
    /// Parent-instance ID measurement.
    ParentInstanceId,
    /// Enclave image signing-certificate measurement.
    ImageSigningCertificate,
}

impl NitroPcrSemantic {
    /// Returns the corresponding standard PCR index.
    pub const fn index(self) -> u8 {
        match self {
            Self::EnclaveImage => 0,
            Self::KernelAndBootstrap => 1,
            Self::Application => 2,
            Self::ParentIamRole => 3,
            Self::ParentInstanceId => 4,
            Self::ImageSigningCertificate => 8,
        }
    }
}

/// Returns the standard Nitro meaning for an index, if one exists.
pub const fn nitro_pcr_semantic(index: u8) -> Option<NitroPcrSemantic> {
    match index {
        0 => Some(NitroPcrSemantic::EnclaveImage),
        1 => Some(NitroPcrSemantic::KernelAndBootstrap),
        2 => Some(NitroPcrSemantic::Application),
        3 => Some(NitroPcrSemantic::ParentIamRole),
        4 => Some(NitroPcrSemantic::ParentInstanceId),
        8 => Some(NitroPcrSemantic::ImageSigningCertificate),
        _ => None,
    }
}

/// Returns whether an index is structurally valid for a Nitro PCR map.
///
/// The parser and policy accept the full `0..=31` range. The semantic helper
/// above intentionally names only the standard PCR0/PCR1/PCR2/PCR3/PCR4/PCR8
/// meanings; deployments choose the exact indexes they require in policy.
pub const fn is_valid_nitro_pcr_index(index: u8) -> bool {
    index <= 31
}

/// Exact SHA-384 PCR measurements required by a caller's policy.
#[derive(Clone, PartialEq, Eq)]
pub struct NitroPcrPolicy {
    required: BTreeMap<u8, [u8; NITRO_SHA384_PCR_BYTES]>,
}

impl fmt::Debug for NitroPcrPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroPcrPolicy")
            .field(
                "required_indexes",
                &self.required.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl NitroPcrPolicy {
    /// Creates an exact policy. PCR4 is not implicitly required; callers select
    /// the indexes appropriate for their deployment and binding contract.
    pub fn new<I>(measurements: I) -> Result<Self, NitroError>
    where
        I: IntoIterator<Item = (u8, [u8; NITRO_SHA384_PCR_BYTES])>,
    {
        let mut required = BTreeMap::new();
        for (index, value) in measurements {
            if !is_valid_nitro_pcr_index(index) || value.iter().all(|byte| *byte == 0) {
                return Err(NitroError::PcrPolicyInvalid);
            }
            if required.insert(index, value).is_some() {
                return Err(NitroError::PcrPolicyInvalid);
            }
        }

        if required.is_empty() {
            return Err(NitroError::PcrPolicyEmpty);
        }

        Ok(Self { required })
    }

    /// Returns the exact required indexes without exposing measurement bytes.
    pub fn required_indexes(&self) -> impl Iterator<Item = u8> + '_ {
        self.required.keys().copied()
    }

    fn verify(&self, document: &NitroAttestationDocument) -> Result<(), NitroError> {
        for (index, expected) in &self.required {
            let actual = document
                .pcrs
                .get(index)
                .ok_or(NitroError::MissingRequiredPcr)?;
            if actual.iter().all(|byte| *byte == 0) {
                return Err(NitroError::AllZeroRequiredPcr);
            }
            if actual != expected {
                return Err(NitroError::PcrMismatch);
            }
        }
        Ok(())
    }
}

/// Bounded policy for offline attestation freshness and exact PCR checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NitroAttestationPolicy {
    pcr_policy: NitroPcrPolicy,
    max_age_ms: u64,
    max_future_skew_ms: u64,
    expected_module_id: Option<String>,
}

impl NitroAttestationPolicy {
    /// Creates an offline policy with conservative freshness bounds.
    pub fn new(pcr_policy: NitroPcrPolicy) -> Self {
        Self {
            pcr_policy,
            max_age_ms: MAX_AGE_MS,
            max_future_skew_ms: MAX_FUTURE_SKEW_MS,
            expected_module_id: None,
        }
    }

    /// Restricts the policy to one exact module identifier.
    pub fn with_module_id(mut self, module_id: impl Into<String>) -> Result<Self, NitroError> {
        let module_id = module_id.into();
        validate_text(&module_id, MAX_MODULE_ID_BYTES, true)
            .map_err(|_| NitroError::InvalidModuleId)?;
        self.expected_module_id = Some(module_id);
        Ok(self)
    }

    /// Applies stricter freshness bounds. Bounds cannot be weakened beyond the
    /// constants used by this offline boundary.
    pub fn with_freshness(
        self,
        max_age_ms: u64,
        max_future_skew_ms: u64,
    ) -> Result<Self, NitroError> {
        if max_age_ms > MAX_AGE_MS || max_future_skew_ms > MAX_FUTURE_SKEW_MS {
            return Err(NitroError::FreshnessPolicyInvalid);
        }
        Ok(Self {
            max_age_ms,
            max_future_skew_ms,
            ..self
        })
    }

    fn verify(&self, document: &NitroAttestationDocument, now_ms: u64) -> Result<(), NitroError> {
        if let Some(expected_module_id) = &self.expected_module_id {
            if &document.module_id != expected_module_id {
                return Err(NitroError::ModuleIdMismatch);
            }
        }

        if document.timestamp_ms > now_ms {
            if document.timestamp_ms - now_ms > self.max_future_skew_ms {
                return Err(NitroError::TimestampFuture);
            }
        } else if now_ms - document.timestamp_ms > self.max_age_ms {
            return Err(NitroError::TimestampExpired);
        }

        self.pcr_policy.verify(document)
    }
}

/// The required certificate-path decision supplied by the deployment trust
/// boundary. This crate intentionally has no default AWS root or collateral
/// implementation, so a signature match alone can never produce this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NitroTrustDecision {
    /// The injected verifier completed its required path/root/collateral checks.
    Verified,
    /// The injected boundary is not configured to complete those checks.
    Unavailable,
}

/// Injected certificate trust boundary for offline Nitro verification.
///
/// Implementations own AWS root selection, certificate-path validation,
/// validity, revocation/collateral, and any provider-specific refresh policy.
/// The SDK never treats fixture labels as roots and never supplies a default
/// accepting implementation.
pub trait NitroCertificateTrustBoundary: Send + Sync {
    fn verify_certificate_path(
        &self,
        document: &NitroAttestationDocument,
    ) -> Result<NitroTrustDecision, NitroError>;
}

/// Status returned only after the complete offline release verification
/// operation passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NitroOfflineVerificationStatus {
    /// Offline cryptographic, trust, policy, freshness, and binding checks passed.
    CoseAndInjectedCertificateTrustVerified,
}

/// Explicitly records that this slice has not consumed durable replay state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NitroOfflineReplayStatus {
    /// Replay consumption is intentionally outside this offline boundary.
    NotConsumed,
}

/// Explicitly records that this slice cannot be used as production provider
/// verification or value-bearing authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NitroOfflineProductionStatus {
    /// Production provider verification is unavailable for this receipt.
    Unavailable,
}

/// Offline structural evidence for one fully composed Nitro release check.
///
/// This type has no public constructor and is deliberately named so it cannot
/// be confused with production attestation or value-bearing authorization. It
/// records that durable replay consumption did not occur and that production
/// provider verification remains unavailable.
#[derive(Clone, PartialEq, Eq)]
pub struct NitroOfflineVerificationReceipt {
    document: NitroAttestationDocument,
    status: NitroOfflineVerificationStatus,
    replay_status: NitroOfflineReplayStatus,
    production_status: NitroOfflineProductionStatus,
}

impl fmt::Debug for NitroOfflineVerificationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroOfflineVerificationReceipt")
            .field("status", &self.status)
            .field("replay_status", &self.replay_status)
            .field("production_status", &self.production_status)
            .field("module_id", &self.document.module_id)
            .field("timestamp_ms", &self.document.timestamp_ms)
            .field("pcr_count", &self.document.pcrs.len())
            .finish()
    }
}

impl NitroOfflineVerificationReceipt {
    /// Returns the verification status.
    pub const fn status(&self) -> NitroOfflineVerificationStatus {
        self.status
    }

    /// Returns the explicit replay-consumption status.
    pub const fn replay_status(&self) -> NitroOfflineReplayStatus {
        self.replay_status
    }

    /// Returns the explicit production-support status.
    pub const fn production_status(&self) -> NitroOfflineProductionStatus {
        self.production_status
    }

    /// Returns the module identifier carried by the checked document.
    pub fn module_id(&self) -> &str {
        &self.document.module_id
    }

    /// Returns the checked attestation timestamp.
    pub const fn timestamp_ms(&self) -> u64 {
        self.document.timestamp_ms
    }

    /// Returns one checked PCR value without exposing the raw document.
    pub fn pcr(&self, index: u8) -> Option<&[u8; NITRO_SHA384_PCR_BYTES]> {
        self.document.pcr(index)
    }
}

/// Parsed AWS Nitro attestation document. This value is explicitly **unverified**:
/// parsing and structural checks do not establish authenticity, certificate
/// trust, PCR policy, freshness, nonce binding, recipient-key binding, or
/// release binding. Those checks are available only through the single
/// composed [`Self::verify_offline`] operation.
///
/// Raw sensitive-adjacent fields are private and intentionally omitted from
/// `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct NitroAttestationDocument {
    module_id: String,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, [u8; NITRO_SHA384_PCR_BYTES]>,
    certificate: Vec<u8>,
    ca_bundle_root_first: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl fmt::Debug for NitroAttestationDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroAttestationDocument")
            .field("module_id", &self.module_id)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("pcr_indexes", &self.pcrs.keys().collect::<Vec<_>>())
            .field("ca_bundle_count", &self.ca_bundle_root_first.len())
            .field("has_public_key", &self.public_key.is_some())
            .field(
                "user_data_len",
                &self.user_data.as_ref().map_or(0, Vec::len),
            )
            .field("has_nonce", &self.nonce.is_some())
            .finish()
    }
}

impl NitroAttestationDocument {
    /// Parses tagged or untagged COSE_Sign1 Nitro input with bounded CBOR.
    pub fn parse(input: &[u8]) -> Result<Self, NitroError> {
        if input.is_empty() || input.len() > MAX_NITRO_ATTESTATION_BYTES {
            return Err(NitroError::InputTooLarge);
        }

        let cose = decode_one(input, MAX_NITRO_ATTESTATION_BYTES)?;
        let cose = match cose {
            Value::Tag(tag, inner) if tag == NITRO_COSE_SIGN1_TAG => *inner,
            Value::Tag(_, _) => return Err(NitroError::CoseInvalidShape),
            other => other,
        };
        let cose_items = match cose {
            Value::Array(items) if items.len() == 4 => items,
            _ => return Err(NitroError::CoseInvalidShape),
        };

        let protected = match &cose_items[0] {
            Value::Bytes(bytes)
                if !bytes.is_empty() && bytes.len() <= MAX_NITRO_OPTIONAL_FIELD_BYTES =>
            {
                bytes.clone()
            }
            Value::Bytes(_) => return Err(NitroError::CoseProtectedHeaderRequired),
            _ => return Err(NitroError::CoseProtectedHeaderRequired),
        };
        let protected_value = decode_one(&protected, MAX_NITRO_OPTIONAL_FIELD_BYTES)?;
        validate_protected_header(&protected_value)?;

        match &cose_items[1] {
            Value::Map(entries) if entries.is_empty() => {}
            Value::Map(_) => return Err(NitroError::CoseUnprotectedHeaderNotEmpty),
            _ => return Err(NitroError::CoseInvalidShape),
        }

        let payload = match &cose_items[2] {
            Value::Bytes(bytes) if !bytes.is_empty() && bytes.len() <= MAX_NITRO_PAYLOAD_BYTES => {
                bytes.clone()
            }
            Value::Bytes(_) => return Err(NitroError::CoseMissingPayload),
            Value::Null => return Err(NitroError::CoseMissingPayload),
            _ => return Err(NitroError::CoseInvalidShape),
        };
        let signature = match &cose_items[3] {
            Value::Bytes(bytes) if bytes.len() == 96 => bytes.clone(),
            Value::Bytes(_) => return Err(NitroError::CoseSignatureLength),
            _ => return Err(NitroError::CoseInvalidShape),
        };

        let fields = decode_attestation_payload(&payload)?;
        let leaf = parse_certificate(&fields.certificate, NitroError::InvalidCertificate)?;
        validate_p384_leaf(&leaf)?;
        let ca_bundle_root_first = parse_ca_bundle(&fields.ca_bundle)?;
        if let Some(public_key) = &fields.public_key {
            validate_recipient_public_key(public_key)?;
        }

        Ok(Self {
            module_id: fields.module_id,
            timestamp_ms: fields.timestamp_ms,
            pcrs: fields.pcrs,
            certificate: fields.certificate,
            ca_bundle_root_first,
            public_key: fields.public_key,
            user_data: fields.user_data,
            nonce: fields.nonce,
            protected,
            payload,
            signature,
        })
    }

    /// Returns the module identifier.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the attestation timestamp in milliseconds since Unix epoch.
    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Returns a PCR value without exposing the complete map in diagnostics.
    pub fn pcr(&self, index: u8) -> Option<&[u8; NITRO_SHA384_PCR_BYTES]> {
        self.pcrs.get(&index)
    }

    /// Returns the indexes present in the document.
    pub fn pcr_indexes(&self) -> impl Iterator<Item = u8> + '_ {
        self.pcrs.keys().copied()
    }

    /// Returns the leaf certificate DER bytes for an injected trust boundary.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// Returns the root-first CA bundle for an injected trust boundary.
    pub fn ca_bundle_root_first(&self) -> impl Iterator<Item = &[u8]> {
        self.ca_bundle_root_first.iter().map(Vec::as_slice)
    }

    /// Returns the attested public-key bytes when present.
    pub fn public_key_der(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// Returns the signed user data when present.
    pub fn user_data(&self) -> Option<&[u8]> {
        self.user_data.as_deref()
    }

    fn verify_nonce(&self, expected_nonce: &[u8]) -> Result<(), NitroError> {
        if expected_nonce.is_empty() || expected_nonce.len() > MAX_NITRO_OPTIONAL_FIELD_BYTES {
            return Err(NitroError::NonceMismatch);
        }
        match &self.nonce {
            Some(nonce) if nonce == expected_nonce => Ok(()),
            Some(_) => Err(NitroError::NonceMismatch),
            None => Err(NitroError::MissingNonce),
        }
    }

    fn verify_attested_recipient_public_key_hash(
        &self,
        expected_hash: [u8; 32],
    ) -> Result<(), NitroError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(NitroError::MissingPublicKey)?;
        let actual_hash: [u8; 32] = Sha256::digest(public_key).into();
        if actual_hash == expected_hash {
            Ok(())
        } else {
            Err(NitroError::PublicKeyMismatch)
        }
    }

    fn verify_release_binding(
        &self,
        expected: &NitroReleaseBinding,
        now_ms: u64,
    ) -> Result<(), NitroError> {
        let user_data = self
            .user_data
            .as_deref()
            .ok_or(NitroError::MissingReleaseBinding)?;
        let actual = NitroReleaseBinding::decode(user_data)?;
        if actual != *expected {
            return Err(NitroError::ReleaseBindingMismatch);
        }
        if actual.expires_at_ms <= now_ms {
            return Err(NitroError::ReleaseBindingExpired);
        }
        Ok(())
    }

    /// Verifies the complete offline release contract in one operation.
    ///
    /// The COSE signature is checked first. Only after signature validity,
    /// injected certificate trust, exact PCR/module policy, freshness, nonce,
    /// recipient-key hash, and release-binding expiry all pass is the receipt
    /// constructed. This prevents a matching untrusted field from being
    /// mistaken for an authenticated authorization result.
    pub fn verify_offline(
        &self,
        policy: &NitroAttestationPolicy,
        trust_boundary: &dyn NitroCertificateTrustBoundary,
        now_ms: u64,
        expected_nonce: &[u8],
        expected_recipient_public_key_hash: [u8; 32],
        expected_release_binding: &NitroReleaseBinding,
    ) -> Result<NitroOfflineVerificationReceipt, NitroError> {
        self.verify_cose_signature()?;
        policy.verify(self, now_ms)?;
        let decision = trust_boundary.verify_certificate_path(self)?;
        if decision != NitroTrustDecision::Verified {
            return Err(NitroError::TrustBoundaryRequired);
        }
        self.verify_nonce(expected_nonce)?;
        self.verify_attested_recipient_public_key_hash(expected_recipient_public_key_hash)?;
        self.verify_release_binding(expected_release_binding, now_ms)?;
        Ok(NitroOfflineVerificationReceipt {
            document: self.clone(),
            status: NitroOfflineVerificationStatus::CoseAndInjectedCertificateTrustVerified,
            replay_status: NitroOfflineReplayStatus::NotConsumed,
            production_status: NitroOfflineProductionStatus::Unavailable,
        })
    }

    fn verify_cose_signature(&self) -> Result<(), NitroError> {
        let leaf = parse_certificate(&self.certificate, NitroError::InvalidCertificate)?;
        let spki = leaf.tbs_certificate().subject_public_key_info();
        let public_key = spki
            .subject_public_key
            .as_bytes()
            .ok_or(NitroError::InvalidCertificate)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| NitroError::InvalidCertificate)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| NitroError::SignatureInvalid)?;
        let sig_structure = cose_sig_structure(&self.protected, &self.payload)?;
        verifying_key
            .verify(&sig_structure, &signature)
            .map_err(|_| NitroError::SignatureInvalid)
    }
}

/// Versioned, domain-separated release-request binding carried in Nitro
/// `user_data`. Raw identifiers are represented only by their hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct NitroReleaseBinding {
    operation_digest: [u8; 32],
    purpose: String,
    kms_key_identifier_hash: [u8; 32],
    policy_version: u32,
    policy_digest: [u8; 32],
    expires_at_ms: u64,
    replay_identity: [u8; 32],
}

impl fmt::Debug for NitroReleaseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroReleaseBinding")
            .field("version", &NITRO_RELEASE_BINDING_VERSION)
            .field("purpose", &self.purpose)
            .field("policy_version", &self.policy_version)
            .field("expires_at_ms", &self.expires_at_ms)
            .field(
                "has_nonzero_replay_identity",
                &self.replay_identity.iter().any(|b| *b != 0),
            )
            .finish()
    }
}

impl NitroReleaseBinding {
    /// Creates a binding from already-hashed operation, KMS key, and policy
    /// identifiers. This constructor never accepts or stores a raw KMS key ID.
    pub fn new(
        operation_digest: [u8; 32],
        purpose: impl Into<String>,
        kms_key_identifier_hash: [u8; 32],
        policy_version: u32,
        policy_digest: [u8; 32],
        expires_at_ms: u64,
        replay_identity: [u8; 32],
    ) -> Result<Self, NitroError> {
        let purpose = purpose.into();
        validate_text(&purpose, MAX_PURPOSE_BYTES, true)
            .map_err(|_| NitroError::ReleaseBindingMalformed)?;
        if operation_digest.iter().all(|byte| *byte == 0)
            || kms_key_identifier_hash.iter().all(|byte| *byte == 0)
            || policy_digest.iter().all(|byte| *byte == 0)
            || policy_version == 0
            || expires_at_ms == 0
            || replay_identity.iter().all(|byte| *byte == 0)
        {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        Ok(Self {
            operation_digest,
            purpose,
            kms_key_identifier_hash,
            policy_version,
            policy_digest,
            expires_at_ms,
            replay_identity,
        })
    }

    /// Encodes the binding deterministically for Nitro `user_data`.
    pub fn encode(&self) -> Result<Vec<u8>, NitroError> {
        let mut output = Vec::with_capacity(320);
        output.extend_from_slice(RELEASE_BINDING_DOMAIN);
        output.extend_from_slice(&NITRO_RELEASE_BINDING_VERSION.to_be_bytes());
        append_u16_len_prefixed(&mut output, self.purpose.as_bytes())?;
        output.extend_from_slice(&self.operation_digest);
        output.extend_from_slice(&self.kms_key_identifier_hash);
        output.extend_from_slice(&self.policy_version.to_be_bytes());
        output.extend_from_slice(&self.policy_digest);
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        output.extend_from_slice(&self.replay_identity);
        if output.len() > MAX_NITRO_OPTIONAL_FIELD_BYTES {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        Ok(output)
    }

    /// Decodes an exact binding and rejects trailing or ambiguous bytes.
    pub fn decode(input: &[u8]) -> Result<Self, NitroError> {
        if input.is_empty() || input.len() > MAX_NITRO_OPTIONAL_FIELD_BYTES {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        let mut cursor = 0usize;
        if !input.starts_with(RELEASE_BINDING_DOMAIN) {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        cursor += RELEASE_BINDING_DOMAIN.len();
        let version = read_u16(input, &mut cursor)?;
        if version != NITRO_RELEASE_BINDING_VERSION {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        let purpose = read_u16_len_prefixed(input, &mut cursor)?;
        let purpose =
            std::str::from_utf8(purpose).map_err(|_| NitroError::ReleaseBindingMalformed)?;
        validate_text(purpose, MAX_PURPOSE_BYTES, true)
            .map_err(|_| NitroError::ReleaseBindingMalformed)?;
        let operation_digest = read_fixed::<32>(input, &mut cursor)?;
        let kms_key_identifier_hash = read_fixed::<32>(input, &mut cursor)?;
        let policy_version = read_u32(input, &mut cursor)?;
        let policy_digest = read_fixed::<32>(input, &mut cursor)?;
        let expires_at_ms = read_u64(input, &mut cursor)?;
        let replay_identity = read_fixed::<32>(input, &mut cursor)?;
        if cursor != input.len() {
            return Err(NitroError::ReleaseBindingMalformed);
        }
        Self::new(
            operation_digest,
            purpose.to_owned(),
            kms_key_identifier_hash,
            policy_version,
            policy_digest,
            expires_at_ms,
            replay_identity,
        )
    }

    /// Returns a domain-separated digest for audit or replay indexing.
    pub fn digest(&self) -> Result<[u8; 32], NitroError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    /// Returns the bound purpose.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Returns the binding expiry in milliseconds.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the bound policy version.
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }
}

/// Exact KMS recipient encryption mechanism accepted by this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NitroKmsKeyEncryptionAlgorithm {
    #[serde(rename = "RSAES_OAEP_SHA_256")]
    RsaesOaepSha256,
}

impl NitroKmsKeyEncryptionAlgorithm {
    /// Returns the AWS wire spelling.
    pub const fn as_str(self) -> &'static str {
        "RSAES_OAEP_SHA_256"
    }
}

/// Transport-neutral KMS recipient request. No network or AWS SDK is used.
#[derive(Clone, PartialEq, Eq)]
pub struct NitroKmsRecipientRequest {
    attestation_document: Vec<u8>,
    algorithm: NitroKmsKeyEncryptionAlgorithm,
}

impl fmt::Debug for NitroKmsRecipientRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroKmsRecipientRequest")
            .field("attestation_document_len", &self.attestation_document.len())
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl NitroKmsRecipientRequest {
    /// Constructs a request from the exact AWS wire algorithm string.
    pub fn from_wire(attestation_document: Vec<u8>, algorithm: &str) -> Result<Self, NitroError> {
        if algorithm != NitroKmsKeyEncryptionAlgorithm::RsaesOaepSha256.as_str() {
            return Err(NitroError::RecipientAlgorithmUnsupported);
        }
        if attestation_document.is_empty() {
            return Err(NitroError::RecipientAttestationMissing);
        }
        if attestation_document.len() > MAX_NITRO_ATTESTATION_BYTES {
            return Err(NitroError::InputTooLarge);
        }
        Ok(Self {
            attestation_document,
            algorithm: NitroKmsKeyEncryptionAlgorithm::RsaesOaepSha256,
        })
    }

    /// Returns the attestation bytes for a transport adapter.
    pub fn attestation_document(&self) -> &[u8] {
        &self.attestation_document
    }

    /// Returns the exact KMS algorithm.
    pub const fn algorithm(&self) -> NitroKmsKeyEncryptionAlgorithm {
        self.algorithm
    }
}

/// Transport-neutral KMS recipient response. Plaintext is never represented.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct NitroKmsRecipientResponse {
    ciphertext_for_recipient: Vec<u8>,
}

impl fmt::Debug for NitroKmsRecipientResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NitroKmsRecipientResponse")
            .field(
                "ciphertext_for_recipient_len",
                &self.ciphertext_for_recipient.len(),
            )
            .finish()
    }
}

impl NitroKmsRecipientResponse {
    /// Constructs a safe response from only the dedicated
    /// `CiphertextForRecipient` field. Raw KMS transport parsing is out of
    /// scope; a future crate-private adapter must call
    /// [`validate_raw_recipient_response`] with the actual raw fields first.
    pub fn from_ciphertext_for_recipient(
        ciphertext_for_recipient: Vec<u8>,
    ) -> Result<Self, NitroError> {
        validate_raw_recipient_response(None, Some(&ciphertext_for_recipient))?;
        Ok(Self {
            ciphertext_for_recipient,
        })
    }

    /// Returns the bounded ciphertext for the attested recipient.
    pub fn ciphertext_for_recipient(&self) -> &[u8] {
        &self.ciphertext_for_recipient
    }
}

/// Validates raw KMS response fields for a future transport adapter without
/// exposing plaintext or a caller-controlled presence boolean publicly.
fn validate_raw_recipient_response(
    plaintext: Option<&[u8]>,
    ciphertext_for_recipient: Option<&[u8]>,
) -> Result<(), NitroError> {
    if plaintext.is_some_and(|value| !value.is_empty()) {
        return Err(NitroError::RecipientPlaintextRejected);
    }
    let ciphertext = ciphertext_for_recipient
        .filter(|value| {
            !value.is_empty() && value.len() <= MAX_NITRO_CIPHERTEXT_FOR_RECIPIENT_BYTES
        })
        .ok_or(NitroError::RecipientCiphertextInvalid)?;
    if ciphertext.is_empty() {
        return Err(NitroError::RecipientCiphertextInvalid);
    }
    Ok(())
}

struct ParsedPayload {
    module_id: String,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, [u8; NITRO_SHA384_PCR_BYTES]>,
    certificate: Vec<u8>,
    ca_bundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

fn decode_one(input: &[u8], max_len: usize) -> Result<Value, NitroError> {
    if input.is_empty() || input.len() > max_len {
        return Err(NitroError::InputTooLarge);
    }
    let mut cursor = Cursor::new(input);
    let value: Value = de::from_reader(&mut cursor).map_err(|_| NitroError::CborMalformed)?;
    if cursor.position() as usize != input.len() {
        return Err(NitroError::CborTrailingData);
    }
    validate_cbor_depth(&value, 0)?;
    Ok(value)
}

fn validate_cbor_depth(value: &Value, depth: usize) -> Result<(), NitroError> {
    if depth > MAX_NITRO_CBOR_DEPTH {
        return Err(NitroError::CborNestingTooDeep);
    }
    let child_depth = depth.checked_add(1).ok_or(NitroError::CborNestingTooDeep)?;
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_cbor_depth(value, child_depth)),
        Value::Map(entries) => entries.iter().try_for_each(|(key, value)| {
            validate_cbor_depth(key, child_depth)?;
            validate_cbor_depth(value, child_depth)
        }),
        Value::Tag(_, value) => validate_cbor_depth(value, child_depth),
        _ => Ok(()),
    }
}

fn validate_protected_header(value: &Value) -> Result<(), NitroError> {
    let entries = match value {
        Value::Map(entries) if !entries.is_empty() => entries,
        Value::Map(_) => return Err(NitroError::CoseProtectedHeaderRequired),
        _ => return Err(NitroError::CborUnsupportedType),
    };
    let mut seen = Vec::with_capacity(entries.len());
    let mut algorithm = None;
    for (key, value) in entries {
        if seen.iter().any(|existing: &Value| existing == key) {
            return Err(NitroError::CborDuplicateMapKey);
        }
        seen.push(key.clone());
        let key = key.as_integer().ok_or(NitroError::CborUnsupportedType)?;
        let key: i128 = key.into();
        if key != 1 {
            return Err(NitroError::CoseUnsupportedAlgorithm);
        }
        let value = value
            .as_integer()
            .ok_or(NitroError::CoseUnsupportedAlgorithm)?;
        let value: i128 = value.into();
        algorithm = Some(value);
    }
    if algorithm != Some(NITRO_COSE_ES384_ALGORITHM as i128) {
        return Err(NitroError::CoseUnsupportedAlgorithm);
    }
    Ok(())
}

fn decode_attestation_payload(payload: &[u8]) -> Result<ParsedPayload, NitroError> {
    let value = decode_one(payload, MAX_NITRO_PAYLOAD_BYTES)?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(NitroError::PayloadFieldType),
    };
    let mut fields: [Option<Value>; 9] = std::array::from_fn(|_| None);
    for (key, value) in entries {
        let key = match key {
            Value::Text(key) => key,
            _ => return Err(NitroError::PayloadFieldType),
        };
        let index = match key.as_str() {
            "module_id" => 0,
            "timestamp" => 1,
            "digest" => 2,
            "pcrs" => 3,
            "certificate" => 4,
            "cabundle" => 5,
            "public_key" => 6,
            "user_data" => 7,
            "nonce" => 8,
            _ => return Err(NitroError::PayloadUnknownField),
        };
        if fields[index].replace(value).is_some() {
            return Err(NitroError::PayloadDuplicateField);
        }
    }

    let module_id = parse_module_id(fields[0].as_ref().ok_or(NitroError::PayloadMissingField)?)?;
    let timestamp_ms = parse_timestamp(fields[1].as_ref().ok_or(NitroError::PayloadMissingField)?)?;
    let digest = parse_text(
        fields[2].as_ref().ok_or(NitroError::PayloadMissingField)?,
        MAX_MODULE_ID_BYTES,
        false,
    )?;
    if digest != "SHA384" {
        return Err(NitroError::InvalidDigest);
    }
    let pcrs = parse_pcrs(fields[3].as_ref().ok_or(NitroError::PayloadMissingField)?)?;
    let certificate = parse_bytes(
        fields[4].as_ref().ok_or(NitroError::PayloadMissingField)?,
        1,
        MAX_NITRO_CERTIFICATE_BYTES,
    )?;
    let ca_bundle =
        parse_ca_bundle_value(fields[5].as_ref().ok_or(NitroError::PayloadMissingField)?)?;
    let public_key = parse_optional_bytes(fields[6].as_ref(), false)?;
    let user_data = parse_optional_bytes(fields[7].as_ref(), true)?;
    let nonce = parse_optional_bytes(fields[8].as_ref(), true)?;

    Ok(ParsedPayload {
        module_id,
        timestamp_ms,
        pcrs,
        certificate,
        ca_bundle,
        public_key,
        user_data,
        nonce,
    })
}

fn parse_module_id(value: &Value) -> Result<String, NitroError> {
    let module_id =
        parse_text(value, MAX_MODULE_ID_BYTES, true).map_err(|_| NitroError::InvalidModuleId)?;
    Ok(module_id.to_owned())
}

fn parse_timestamp(value: &Value) -> Result<u64, NitroError> {
    let integer = value.as_integer().ok_or(NitroError::InvalidTimestamp)?;
    let timestamp: i128 = integer.into();
    let timestamp = u64::try_from(timestamp).map_err(|_| NitroError::InvalidTimestamp)?;
    if timestamp == 0 {
        return Err(NitroError::InvalidTimestamp);
    }
    Ok(timestamp)
}

fn parse_text(value: &Value, max_len: usize, non_empty: bool) -> Result<&str, NitroError> {
    let text = match value {
        Value::Text(text) => text.as_str(),
        _ => return Err(NitroError::PayloadFieldType),
    };
    validate_text(text, max_len, non_empty).map_err(|_| NitroError::PayloadFieldLength)?;
    Ok(text)
}

fn validate_text(text: &str, max_len: usize, non_empty: bool) -> Result<(), ()> {
    if (non_empty && text.is_empty()) || text.len() > max_len || text.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

fn parse_bytes(value: &Value, min_len: usize, max_len: usize) -> Result<Vec<u8>, NitroError> {
    let bytes = match value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(NitroError::PayloadFieldType),
    };
    if bytes.len() < min_len || bytes.len() > max_len {
        return Err(NitroError::PayloadFieldLength);
    }
    Ok(bytes.clone())
}

fn parse_optional_bytes(
    value: Option<&Value>,
    allow_empty: bool,
) -> Result<Option<Vec<u8>>, NitroError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let min_len = usize::from(!allow_empty);
    Ok(Some(parse_bytes(
        value,
        min_len,
        MAX_NITRO_OPTIONAL_FIELD_BYTES,
    )?))
}

fn parse_pcrs(value: &Value) -> Result<BTreeMap<u8, [u8; NITRO_SHA384_PCR_BYTES]>, NitroError> {
    let entries = match value {
        Value::Map(entries) if !entries.is_empty() && entries.len() <= 32 => entries,
        Value::Map(_) => return Err(NitroError::PayloadFieldLength),
        _ => return Err(NitroError::PayloadFieldType),
    };
    let mut pcrs = BTreeMap::new();
    for (key, value) in entries {
        let index = key.as_integer().ok_or(NitroError::InvalidPcrIndex)?;
        let index: i128 = index.into();
        let index = u8::try_from(index).map_err(|_| NitroError::InvalidPcrIndex)?;
        if !is_valid_nitro_pcr_index(index) {
            return Err(NitroError::InvalidPcrIndex);
        }
        let bytes = parse_bytes(value, NITRO_SHA384_PCR_BYTES, NITRO_SHA384_PCR_BYTES)?;
        let bytes: [u8; NITRO_SHA384_PCR_BYTES] =
            bytes.try_into().map_err(|_| NitroError::InvalidPcrValue)?;
        if pcrs.insert(index, bytes).is_some() {
            return Err(NitroError::CborDuplicateMapKey);
        }
    }
    Ok(pcrs)
}

fn parse_ca_bundle_value(value: &Value) -> Result<Vec<Vec<u8>>, NitroError> {
    let entries = match value {
        Value::Array(entries)
            if !entries.is_empty() && entries.len() <= MAX_NITRO_CA_BUNDLE_CERTIFICATES =>
        {
            entries
        }
        Value::Array(_) => return Err(NitroError::InvalidCaBundle),
        _ => return Err(NitroError::PayloadFieldType),
    };
    let mut bundle = Vec::with_capacity(entries.len());
    for value in entries {
        let certificate = parse_bytes(value, 1, MAX_NITRO_CERTIFICATE_BYTES)?;
        parse_certificate(&certificate, NitroError::InvalidCaBundle)?;
        if bundle.iter().any(|existing| existing == &certificate) {
            return Err(NitroError::InvalidCaBundle);
        }
        bundle.push(certificate);
    }
    parse_ca_bundle(&bundle)
}

fn parse_ca_bundle(value: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, NitroError> {
    if value.is_empty() || value.len() > MAX_NITRO_CA_BUNDLE_CERTIFICATES {
        return Err(NitroError::InvalidCaBundle);
    }

    // AWS encodes the CA bundle root first. This is only a structural
    // root-candidate check; path, signature, validity, collateral, and trust
    // decisions remain the responsibility of the injected boundary.
    let root = parse_certificate(&value[0], NitroError::InvalidCaBundle)?;
    let tbs = root.tbs_certificate();
    if tbs.subject() != tbs.issuer() {
        return Err(NitroError::InvalidCaBundle);
    }
    let basic_constraints = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|_| NitroError::InvalidCaBundle)?
        .ok_or(NitroError::InvalidCaBundle)?;
    if !basic_constraints.1.ca {
        return Err(NitroError::InvalidCaBundle);
    }
    Ok(value.to_vec())
}

fn parse_certificate(bytes: &[u8], error: NitroError) -> Result<Certificate, NitroError> {
    if bytes.is_empty() || bytes.len() > MAX_NITRO_CERTIFICATE_BYTES {
        return Err(error);
    }
    Certificate::from_der(bytes).map_err(|_| error)
}

fn validate_p384_leaf(certificate: &Certificate) -> Result<(), NitroError> {
    let spki = certificate.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != EC_PUBLIC_KEY_OID {
        return Err(NitroError::InvalidCertificate);
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    if curve != Some(P384_OID) {
        return Err(NitroError::InvalidCertificate);
    }
    let public_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(NitroError::InvalidCertificate)?;
    VerifyingKey::from_sec1_bytes(public_key).map_err(|_| NitroError::InvalidCertificate)?;
    Ok(())
}

fn validate_recipient_public_key(bytes: &[u8]) -> Result<(), NitroError> {
    if bytes.is_empty() || bytes.len() > MAX_NITRO_OPTIONAL_FIELD_BYTES {
        return Err(NitroError::InvalidRecipientPublicKey);
    }
    let spki: SubjectPublicKeyInfoOwned = SubjectPublicKeyInfoOwned::from_der(bytes)
        .map_err(|_| NitroError::InvalidRecipientPublicKey)?;
    if spki.algorithm.oid != RSA_ENCRYPTION_OID {
        return Err(NitroError::InvalidRecipientPublicKey);
    }
    let parameters_are_null = spki
        .algorithm
        .parameters
        .as_ref()
        .map(|parameters| parameters.to_ref().is_null())
        .unwrap_or(false);
    if !parameters_are_null {
        return Err(NitroError::InvalidRecipientPublicKey);
    }
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or(NitroError::InvalidRecipientPublicKey)?;
    if key_bits.is_empty() {
        return Err(NitroError::InvalidRecipientPublicKey);
    }

    let rsa_public_key =
        <&SequenceRef>::from_der(key_bits).map_err(|_| NitroError::InvalidRecipientPublicKey)?;
    let (modulus, remaining) = UintRef::from_der_partial(rsa_public_key.as_bytes())
        .map_err(|_| NitroError::InvalidRecipientPublicKey)?;
    let (exponent, remaining) =
        UintRef::from_der_partial(remaining).map_err(|_| NitroError::InvalidRecipientPublicKey)?;
    if !remaining.is_empty() {
        return Err(NitroError::InvalidRecipientPublicKey);
    }

    let modulus_bytes = modulus.as_bytes();
    let modulus_bits = modulus_bytes
        .first()
        .and_then(|first| {
            modulus_bytes
                .len()
                .checked_mul(8)
                .and_then(|bits| bits.checked_sub(first.leading_zeros() as usize))
        })
        .ok_or(NitroError::InvalidRecipientPublicKey)?;
    if modulus_bits < MIN_NITRO_RSA_MODULUS_BITS
        || modulus_bytes.last().is_none_or(|byte| byte & 1 == 0)
    {
        return Err(NitroError::InvalidRecipientPublicKey);
    }

    let exponent_bytes = exponent.as_bytes();
    if exponent_bytes.is_empty() || exponent_bytes.len() > std::mem::size_of::<u64>() {
        return Err(NitroError::InvalidRecipientPublicKey);
    }
    let mut exponent_value = 0u64;
    for byte in exponent_bytes {
        exponent_value = exponent_value
            .checked_shl(8)
            .and_then(|value| value.checked_add(u64::from(*byte)))
            .ok_or(NitroError::InvalidRecipientPublicKey)?;
    }
    if exponent_value < 3 || exponent_value.is_multiple_of(2) {
        return Err(NitroError::InvalidRecipientPublicKey);
    }
    Ok(())
}

fn cose_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, NitroError> {
    let value = Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut encoded = Vec::new();
    ser::into_writer(&value, &mut encoded).map_err(|_| NitroError::CborMalformed)?;
    Ok(encoded)
}

fn append_u16_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), NitroError> {
    let length = u16::try_from(value.len()).map_err(|_| NitroError::ReleaseBindingMalformed)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn read_fixed<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], NitroError> {
    let end = cursor
        .checked_add(N)
        .ok_or(NitroError::ReleaseBindingMalformed)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(NitroError::ReleaseBindingMalformed)?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| NitroError::ReleaseBindingMalformed)
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, NitroError> {
    Ok(u16::from_be_bytes(read_fixed(input, cursor)?))
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, NitroError> {
    Ok(u32::from_be_bytes(read_fixed(input, cursor)?))
}

fn read_u64(input: &[u8], cursor: &mut usize) -> Result<u64, NitroError> {
    Ok(u64::from_be_bytes(read_fixed(input, cursor)?))
}

fn read_u16_len_prefixed<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], NitroError> {
    let length = usize::from(read_u16(input, cursor)?);
    let end = cursor
        .checked_add(length)
        .ok_or(NitroError::ReleaseBindingMalformed)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(NitroError::ReleaseBindingMalformed)?;
    *cursor = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::{signature::Signer, SigningKey};

    const NOW_MS: u64 = 1_735_689_600_000;
    // Test-only deterministic material. This is not an AWS certificate, root,
    // or provenance claim; it exists only to exercise local P-384 verification.
    const PRIVATE_SCALAR: [u8; 48] = [
        0x4c, 0x23, 0xe0, 0x18, 0x35, 0x5c, 0xfa, 0x33, 0xb7, 0x39, 0x99, 0x48, 0xbf, 0xb5, 0xf7,
        0x6d, 0x03, 0xdf, 0x58, 0xab, 0xf9, 0x31, 0xdd, 0x9c, 0xa4, 0x8a, 0x4b, 0x5c, 0xc9, 0xe3,
        0xb5, 0xd8, 0xae, 0xc3, 0xae, 0x8b, 0xda, 0x98, 0x3d, 0x3c, 0x90, 0x54, 0x66, 0x0c, 0x45,
        0xa1, 0xf1, 0xd2,
    ];
    const LEAF_CERTIFICATE_HEX: &str = "308202143082019aa0030201020214518a4cc1a7ce1627e5286cb842c4dfcfe2b48fdf300a06082a8648ce3d04030330413120301e06035504030c17436f6e7869616e204e6974726f20746573742d6f6e6c793110300e060355040a0c07436f6e7869616e310b3009060355040613025553301e170d3236303732323134313834325a170d3336303731393134313834325a30413120301e06035504030c17436f6e7869616e204e6974726f20746573742d6f6e6c793110300e060355040a0c07436f6e7869616e310b30090603550406130255533076301006072a8648ce3d020106052b81040022036200048c5817239b9f7b491c98c7ab6d827192e6e1c5148a5ad68c1795d8d8e2c68cedd59701d73358992dd358061fddbdacf9992ebfb3348c353d886418dcd16b6afb62217a127ad1ff4e4368679eb6c249a71cb886368862fcb66614edf736bd8285a3533051301d0603551d0e0416041446dee076224aa00d8119499015b220ff185c6428301f0603551d2304183016801446dee076224aa00d8119499015b220ff185c6428300f0603551d130101ff040530030101ff300a06082a8648ce3d0403030368003065023043afbf06b88f5dd2d82e62ceddef46ca6ed1da3b9bd5847ab03c6531643c7643da2ba52c6017b4f5e0c5625b34d81c380231008f724cc2902b0a0a9ac948bae6ced5b80bff966f1ed1d48a221d29b625f36e1544221f8e27c52791c98d8d995deb246c";
    const RECIPIENT_PUBLIC_KEY_HEX: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b6c42c515f10a6aaf282c63edbe24243a170f3fa2633bd4833637f47ca4f6f36e03a5d29efc3191ac80f390d874b39e30f414fcec1fca0ed81e547edc2cd382c76f61c9018973db9fa537972a7c701f6b77e0982dfc15fc01927ee5e7cd94b4f599ff07013a7c8281bdf22dcbc9ad7cabb7c4311c982f58edb7213ad4558b332266d743aed8192d1884cadb8b14739a8dada66dc970806d9c7ac450cb13d0d7c575fb198534fc61bc41bc0f0574e0e0130c7bbbfbdfdc9f6a6e2e3e2aff1cbeac89ba57884528d55cfb08327a1e8c89f4e003cf2888e933241d9d695bcbbacdc90b44e3e095fa37058ea25b13f5e295cbeac6de838ab8c50af61e298975b872f0203010001";

    struct AcceptingTrustBoundary;

    impl NitroCertificateTrustBoundary for AcceptingTrustBoundary {
        fn verify_certificate_path(
            &self,
            _document: &NitroAttestationDocument,
        ) -> Result<NitroTrustDecision, NitroError> {
            Ok(NitroTrustDecision::Verified)
        }
    }

    struct RejectingTrustBoundary;

    impl NitroCertificateTrustBoundary for RejectingTrustBoundary {
        fn verify_certificate_path(
            &self,
            _document: &NitroAttestationDocument,
        ) -> Result<NitroTrustDecision, NitroError> {
            Err(NitroError::TrustBoundaryRejected)
        }
    }

    struct UnavailableTrustBoundary;

    impl NitroCertificateTrustBoundary for UnavailableTrustBoundary {
        fn verify_certificate_path(
            &self,
            _document: &NitroAttestationDocument,
        ) -> Result<NitroTrustDecision, NitroError> {
            Ok(NitroTrustDecision::Unavailable)
        }
    }

    fn fixture_pcr(value: u8) -> [u8; NITRO_SHA384_PCR_BYTES] {
        [value; NITRO_SHA384_PCR_BYTES]
    }

    fn fixture_binding() -> NitroReleaseBinding {
        NitroReleaseBinding::new(
            [1; 32],
            "KMS_RELEASE",
            [2; 32],
            7,
            [3; 32],
            NOW_MS + 60_000,
            [4; 32],
        )
        .expect("test binding")
    }

    fn build_fixture() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let signing_key = SigningKey::from_slice(&PRIVATE_SCALAR).expect("test private scalar");
        let leaf_der = hex::decode(LEAF_CERTIFICATE_HEX).expect("test leaf certificate");
        let recipient_public_key =
            hex::decode(RECIPIENT_PUBLIC_KEY_HEX).expect("test recipient public key");
        let protected = {
            let mut bytes = Vec::new();
            ser::into_writer(
                &Value::Map(vec![(
                    Value::Integer(1.into()),
                    Value::Integer((-35i64).into()),
                )]),
                &mut bytes,
            )
            .expect("protected header");
            bytes
        };
        let binding = fixture_binding().encode().expect("binding bytes");
        let payload_value = Value::Map(vec![
            (
                Value::Text("module_id".into()),
                Value::Text("test-module".into()),
            ),
            (
                Value::Text("timestamp".into()),
                Value::Integer(NOW_MS.into()),
            ),
            (Value::Text("digest".into()), Value::Text("SHA384".into())),
            (
                Value::Text("pcrs".into()),
                Value::Map(vec![
                    (
                        Value::Integer(0.into()),
                        Value::Bytes(fixture_pcr(1).to_vec()),
                    ),
                    (
                        Value::Integer(1.into()),
                        Value::Bytes(fixture_pcr(2).to_vec()),
                    ),
                    (
                        Value::Integer(2.into()),
                        Value::Bytes(fixture_pcr(3).to_vec()),
                    ),
                    (
                        Value::Integer(3.into()),
                        Value::Bytes(fixture_pcr(4).to_vec()),
                    ),
                    (
                        Value::Integer(8.into()),
                        Value::Bytes(fixture_pcr(8).to_vec()),
                    ),
                ]),
            ),
            (
                Value::Text("certificate".into()),
                Value::Bytes(leaf_der.clone()),
            ),
            (
                Value::Text("cabundle".into()),
                Value::Array(vec![Value::Bytes(leaf_der.clone())]),
            ),
            (
                Value::Text("public_key".into()),
                Value::Bytes(recipient_public_key.clone()),
            ),
            (Value::Text("user_data".into()), Value::Bytes(binding)),
            (Value::Text("nonce".into()), Value::Bytes(vec![9, 8, 7])),
        ]);
        let mut payload = Vec::new();
        ser::into_writer(&payload_value, &mut payload).expect("payload");
        let sig_structure = cose_sig_structure(&protected, &payload).expect("sig structure");
        let signature: p384::ecdsa::Signature = signing_key.sign(&sig_structure);
        let signature = signature.to_bytes().to_vec();
        let cose = Value::Tag(
            NITRO_COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(Vec::new()),
                Value::Bytes(payload),
                Value::Bytes(signature),
            ])),
        );
        let mut encoded = Vec::new();
        ser::into_writer(&cose, &mut encoded).expect("COSE");
        let public_key_hash = Sha256::digest(&recipient_public_key).into();
        (encoded, leaf_der, public_key_hash)
    }

    fn rewrite_cose<F>(encoded: &[u8], mutate: F) -> Vec<u8>
    where
        F: FnOnce(&mut Value),
    {
        let mut value = decode_one(encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode COSE");
        mutate(&mut value);
        let mut output = Vec::new();
        ser::into_writer(&value, &mut output).expect("encode COSE");
        output
    }

    fn cose_items_mut(value: &mut Value) -> &mut Vec<Value> {
        match value {
            Value::Tag(_, inner) => match inner.as_mut() {
                Value::Array(items) => items,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }

    fn rewrite_payload<F>(encoded: &[u8], mutate: F) -> Vec<u8>
    where
        F: FnOnce(&mut Value),
    {
        let mut value = decode_one(encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode COSE");
        let payload = match &value {
            Value::Tag(_, inner) => match inner.as_ref() {
                Value::Array(items) => match &items[2] {
                    Value::Bytes(payload) => payload.clone(),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let mut payload_value = decode_one(&payload, MAX_NITRO_PAYLOAD_BYTES).expect("payload");
        mutate(&mut payload_value);
        let mut payload = Vec::new();
        ser::into_writer(&payload_value, &mut payload).expect("encode payload");
        replace_payload(&mut value, payload);
        let mut output = Vec::new();
        ser::into_writer(&value, &mut output).expect("encode COSE");
        output
    }

    fn payload_field_mut<'a>(payload: &'a mut Value, name: &str) -> &'a mut Value {
        match payload {
            Value::Map(entries) => entries
                .iter_mut()
                .find(|(key, _)| key == &Value::Text(name.to_owned()))
                .map(|(_, value)| value)
                .expect("fixture field"),
            _ => unreachable!(),
        }
    }

    fn der_length(length: usize) -> Vec<u8> {
        if length < 128 {
            return vec![length as u8];
        }
        let mut bytes = Vec::new();
        let mut remaining = length;
        while remaining != 0 {
            bytes.push((remaining & 0xff) as u8);
            remaining >>= 8;
        }
        bytes.reverse();
        let mut output = vec![0x80 | bytes.len() as u8];
        output.extend_from_slice(&bytes);
        output
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        output.extend_from_slice(&der_length(content.len()));
        output.extend_from_slice(content);
        output
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        der_tlv(0x30, content)
    }

    fn der_integer(value: &[u8]) -> Vec<u8> {
        let mut content = if value.is_empty() {
            vec![0]
        } else {
            value.to_vec()
        };
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        der_tlv(0x02, &content)
    }

    fn rsa_spki_with_key_bits(key_bits: &[u8], parameters: &[u8]) -> Vec<u8> {
        let algorithm_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        let algorithm = der_sequence(&[algorithm_oid.as_slice(), parameters].concat());
        let mut bit_string_content = vec![0];
        bit_string_content.extend_from_slice(key_bits);
        let bit_string = der_tlv(0x03, &bit_string_content);
        der_sequence(&[algorithm, bit_string].concat())
    }

    fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let rsa_public_key = der_sequence(&[der_integer(modulus), der_integer(exponent)].concat());
        rsa_spki_with_key_bits(&rsa_public_key, &[0x05, 0x00])
    }

    fn fixture_rsa_modulus() -> Vec<u8> {
        let public_key = hex::decode(RECIPIENT_PUBLIC_KEY_HEX).expect("recipient key");
        let spki = SubjectPublicKeyInfoOwned::from_der(&public_key).expect("SPKI");
        let key_bits = spki.subject_public_key.as_bytes().expect("key bits");
        let rsa_public_key = <&SequenceRef>::from_der(key_bits).expect("RSA key");
        let (modulus, _) = UintRef::from_der_partial(rsa_public_key.as_bytes()).expect("modulus");
        modulus.as_bytes().to_vec()
    }

    #[test]
    fn parses_tagged_and_untagged_cose_with_real_p384_signature() {
        let (encoded, _, _) = build_fixture();
        let document = NitroAttestationDocument::parse(&encoded).expect("fixture parses");
        assert_eq!(document.module_id(), "test-module");
        assert!(document.pcr(8).is_some());
        assert_eq!(nitro_pcr_semantic(0), Some(NitroPcrSemantic::EnclaveImage));
        assert_eq!(
            nitro_pcr_semantic(4),
            Some(NitroPcrSemantic::ParentInstanceId)
        );
        assert_eq!(
            nitro_pcr_semantic(8),
            Some(NitroPcrSemantic::ImageSigningCertificate)
        );
        assert_eq!(nitro_pcr_semantic(5), None);
        assert!(document.verify_nonce(&[9, 8, 7]).is_ok());

        let value: Value = decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode");
        let untagged = match value {
            Value::Tag(_, inner) => {
                let mut bytes = Vec::new();
                ser::into_writer(&*inner, &mut bytes).expect("untag");
                bytes
            }
            _ => unreachable!(),
        };
        assert!(NitroAttestationDocument::parse(&untagged).is_ok());
    }

    #[test]
    fn rejects_malformed_cose_bounds_and_payload_types() {
        let (encoded, _, _) = build_fixture();
        assert_eq!(
            NitroAttestationDocument::parse(&[]),
            Err(NitroError::InputTooLarge)
        );
        assert_eq!(
            NitroAttestationDocument::parse(&[0xff]),
            Err(NitroError::CborMalformed)
        );
        assert_eq!(
            NitroAttestationDocument::parse(&vec![0; MAX_NITRO_ATTESTATION_BYTES + 1]),
            Err(NitroError::InputTooLarge)
        );

        let short_signature = rewrite_cose(&encoded, |value| {
            cose_items_mut(value)[3] = Value::Bytes(vec![0; 95]);
        });
        assert_eq!(
            NitroAttestationDocument::parse(&short_signature),
            Err(NitroError::CoseSignatureLength)
        );

        let empty_protected = rewrite_cose(&encoded, |value| {
            cose_items_mut(value)[0] = Value::Bytes(Vec::new());
        });
        assert_eq!(
            NitroAttestationDocument::parse(&empty_protected),
            Err(NitroError::CoseProtectedHeaderRequired)
        );

        let malformed_protected = rewrite_cose(&encoded, |value| {
            cose_items_mut(value)[0] = Value::Bytes(vec![0xff]);
        });
        assert_eq!(
            NitroAttestationDocument::parse(&malformed_protected),
            Err(NitroError::CborMalformed)
        );

        let nonempty_unprotected = rewrite_cose(&encoded, |value| {
            cose_items_mut(value)[1] =
                Value::Map(vec![(Value::Integer(4.into()), Value::Integer(1.into()))]);
        });
        assert_eq!(
            NitroAttestationDocument::parse(&nonempty_unprotected),
            Err(NitroError::CoseUnprotectedHeaderNotEmpty)
        );

        let wrong_payload_shape = rewrite_cose(&encoded, |value| {
            cose_items_mut(value)[2] = Value::Text("not-bytes".into());
        });
        assert_eq!(
            NitroAttestationDocument::parse(&wrong_payload_shape),
            Err(NitroError::CoseInvalidShape)
        );

        let wrong_timestamp_type = rewrite_payload(&encoded, |payload| {
            *payload_field_mut(payload, "timestamp") = Value::Text("milliseconds".into());
        });
        assert_eq!(
            NitroAttestationDocument::parse(&wrong_timestamp_type),
            Err(NitroError::InvalidTimestamp)
        );

        let wrong_digest = rewrite_payload(&encoded, |payload| {
            *payload_field_mut(payload, "digest") = Value::Text("SHA256".into());
        });
        assert_eq!(
            NitroAttestationDocument::parse(&wrong_digest),
            Err(NitroError::InvalidDigest)
        );

        let wrong_pcr_length = rewrite_payload(&encoded, |payload| {
            let pcrs = payload_field_mut(payload, "pcrs");
            match pcrs {
                Value::Map(entries) => entries[0].1 = Value::Bytes(vec![0; 47]),
                _ => unreachable!(),
            }
        });
        assert_eq!(
            NitroAttestationDocument::parse(&wrong_pcr_length),
            Err(NitroError::PayloadFieldLength)
        );

        let invalid_public_key = rewrite_payload(&encoded, |payload| {
            *payload_field_mut(payload, "public_key") = Value::Bytes(vec![1, 2, 3]);
        });
        assert_eq!(
            NitroAttestationDocument::parse(&invalid_public_key),
            Err(NitroError::InvalidRecipientPublicKey)
        );
    }

    #[test]
    fn rejects_deeply_nested_bounded_cbor() {
        let mut value = Value::Null;
        for _ in 0..=MAX_NITRO_CBOR_DEPTH {
            value = Value::Array(vec![value]);
        }
        let mut encoded = Vec::new();
        ser::into_writer(&value, &mut encoded).expect("nested CBOR");
        assert_eq!(
            decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES),
            Err(NitroError::CborNestingTooDeep)
        );
    }

    #[test]
    fn rejects_missing_payload_wrong_algorithm_duplicates_and_trailing_data() {
        let (encoded, _, _) = build_fixture();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            NitroAttestationDocument::parse(&trailing),
            Err(NitroError::CborTrailingData)
        );

        let mut missing_value: Value =
            decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode");
        match &mut missing_value {
            Value::Tag(_, inner) => match inner.as_mut() {
                Value::Array(items) => items[2] = Value::Null,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let mut missing_payload = Vec::new();
        ser::into_writer(&missing_value, &mut missing_payload).expect("encode");
        assert_eq!(
            NitroAttestationDocument::parse(&missing_payload),
            Err(NitroError::CoseMissingPayload)
        );

        let mut wrong_value: Value =
            decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode");
        let wrong_protected = {
            let mut bytes = Vec::new();
            ser::into_writer(
                &Value::Map(vec![(
                    Value::Integer(1.into()),
                    Value::Integer((-7i64).into()),
                )]),
                &mut bytes,
            )
            .expect("wrong alg");
            bytes
        };
        match &mut wrong_value {
            Value::Tag(_, inner) => match inner.as_mut() {
                Value::Array(items) => items[0] = Value::Bytes(wrong_protected),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let mut wrong_alg = Vec::new();
        ser::into_writer(&wrong_value, &mut wrong_alg).expect("encode");
        assert_eq!(
            NitroAttestationDocument::parse(&wrong_alg),
            Err(NitroError::CoseUnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate_payload_fields_and_invalid_pcrs() {
        let (encoded, _, _) = build_fixture();
        let payload = match decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode") {
            Value::Tag(_, inner) => match *inner {
                Value::Array(items) => match items[2].clone() {
                    Value::Bytes(payload) => payload,
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let mut payload_value = decode_one(&payload, MAX_NITRO_PAYLOAD_BYTES).expect("payload");
        match &mut payload_value {
            Value::Map(map) => map.push((Value::Text("unknown".into()), Value::Bool(true))),
            _ => unreachable!(),
        }
        let mut unknown_payload = Vec::new();
        ser::into_writer(&payload_value, &mut unknown_payload).expect("payload encode");
        let mut unknown_value = decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode");
        replace_payload(&mut unknown_value, unknown_payload);
        let mut unknown = Vec::new();
        ser::into_writer(&unknown_value, &mut unknown).expect("encode");
        assert_eq!(
            NitroAttestationDocument::parse(&unknown),
            Err(NitroError::PayloadUnknownField)
        );

        match &mut payload_value {
            Value::Map(map) => {
                map.pop();
                map.push((Value::Text("digest".into()), Value::Text("SHA384".into())));
            }
            _ => unreachable!(),
        }
        let mut duplicate_payload = Vec::new();
        ser::into_writer(&payload_value, &mut duplicate_payload).expect("payload encode");
        let mut duplicate_value =
            decode_one(&encoded, MAX_NITRO_ATTESTATION_BYTES).expect("decode");
        replace_payload(&mut duplicate_value, duplicate_payload);
        let mut duplicate = Vec::new();
        ser::into_writer(&duplicate_value, &mut duplicate).expect("encode");
        assert_eq!(
            NitroAttestationDocument::parse(&duplicate),
            Err(NitroError::PayloadDuplicateField)
        );

        let nonsemantic_pcrs = rewrite_payload(&encoded, |payload| {
            let pcrs = payload_field_mut(payload, "pcrs");
            match pcrs {
                Value::Map(entries) => {
                    entries.push((
                        Value::Integer(5.into()),
                        Value::Bytes(fixture_pcr(5).to_vec()),
                    ));
                    entries.push((
                        Value::Integer(31.into()),
                        Value::Bytes(fixture_pcr(31).to_vec()),
                    ));
                }
                _ => unreachable!(),
            }
        });
        let parsed = NitroAttestationDocument::parse(&nonsemantic_pcrs).expect("PCR range");
        assert_eq!(parsed.pcr(5), Some(&fixture_pcr(5)));
        assert_eq!(parsed.pcr(31), Some(&fixture_pcr(31)));
        assert!(NitroPcrPolicy::new([(5, fixture_pcr(5)), (31, fixture_pcr(31))]).is_ok());

        let rejected_pcr = rewrite_payload(&encoded, |payload| {
            let pcrs = payload_field_mut(payload, "pcrs");
            match pcrs {
                Value::Map(entries) => entries[0].0 = Value::Integer(32.into()),
                _ => unreachable!(),
            }
        });
        assert_eq!(
            NitroAttestationDocument::parse(&rejected_pcr),
            Err(NitroError::InvalidPcrIndex)
        );
    }

    fn replace_payload(value: &mut Value, payload: Vec<u8>) {
        match value {
            Value::Tag(_, inner) => match inner.as_mut() {
                Value::Array(items) => items[2] = Value::Bytes(payload),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }

    #[test]
    fn verifies_policy_binding_nonce_public_key_and_injected_trust() {
        let (encoded, _, public_key_hash) = build_fixture();
        let document = NitroAttestationDocument::parse(&encoded).expect("fixture parses");
        let policy = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([
                (0, fixture_pcr(1)),
                (1, fixture_pcr(2)),
                (2, fixture_pcr(3)),
                (3, fixture_pcr(4)),
                (8, fixture_pcr(8)),
            ])
            .expect("PCR policy"),
        );
        assert!(NitroPcrPolicy::new([(5, fixture_pcr(5))]).is_ok());
        let verified = document
            .verify_offline(
                &policy,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                public_key_hash,
                &fixture_binding(),
            )
            .expect("offline verification");
        assert_eq!(
            verified.status(),
            NitroOfflineVerificationStatus::CoseAndInjectedCertificateTrustVerified
        );
        assert_eq!(
            verified.replay_status(),
            NitroOfflineReplayStatus::NotConsumed
        );
        assert_eq!(
            verified.production_status(),
            NitroOfflineProductionStatus::Unavailable
        );
        document
            .verify_release_binding(&fixture_binding(), NOW_MS)
            .expect("binding");
        document
            .verify_attested_recipient_public_key_hash(public_key_hash)
            .expect("recipient key");
        let module_policy = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([(0, fixture_pcr(1))]).expect("module policy"),
        )
        .with_module_id("different-module")
        .expect("module policy id");
        assert_eq!(
            document.verify_offline(
                &module_policy,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                public_key_hash,
                &fixture_binding(),
            ),
            Err(NitroError::ModuleIdMismatch)
        );
        document.verify_cose_signature().expect("COSE signature");
        assert_eq!(
            document.verify_offline(
                &policy,
                &RejectingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                public_key_hash,
                &fixture_binding(),
            ),
            Err(NitroError::TrustBoundaryRejected)
        );
        assert_eq!(
            document.verify_offline(
                &policy,
                &UnavailableTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                public_key_hash,
                &fixture_binding(),
            ),
            Err(NitroError::TrustBoundaryRequired)
        );
        assert_eq!(
            document.verify_nonce(&[9, 8, 6]),
            Err(NitroError::NonceMismatch)
        );
        assert_eq!(
            document.verify_attested_recipient_public_key_hash([0; 32]),
            Err(NitroError::PublicKeyMismatch)
        );
        assert_eq!(
            document.verify_release_binding(
                &NitroReleaseBinding::new(
                    [9; 32],
                    "KMS_RELEASE",
                    [2; 32],
                    7,
                    [3; 32],
                    NOW_MS + 60_000,
                    [4; 32],
                )
                .expect("mismatched binding"),
                NOW_MS,
            ),
            Err(NitroError::ReleaseBindingMismatch)
        );

        let mut missing_nonce = document.clone();
        missing_nonce.nonce = None;
        assert_eq!(
            missing_nonce.verify_nonce(&[9, 8, 7]),
            Err(NitroError::MissingNonce)
        );
        let mut missing_public_key = document.clone();
        missing_public_key.public_key = None;
        assert_eq!(
            missing_public_key.verify_attested_recipient_public_key_hash(public_key_hash),
            Err(NitroError::MissingPublicKey)
        );
    }

    #[test]
    fn invalid_cose_signature_cannot_be_compensated_by_matching_bindings_or_trust() {
        let (encoded, _, public_key_hash) = build_fixture();
        let invalid_signature = rewrite_cose(&encoded, |value| {
            let signature = match &mut cose_items_mut(value)[3] {
                Value::Bytes(signature) => signature,
                _ => unreachable!(),
            };
            signature[0] ^= 0x01;
        });
        let document = NitroAttestationDocument::parse(&invalid_signature).expect("parse");
        let policy = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([
                (0, fixture_pcr(1)),
                (1, fixture_pcr(2)),
                (2, fixture_pcr(3)),
                (3, fixture_pcr(4)),
                (8, fixture_pcr(8)),
            ])
            .expect("PCR policy"),
        );
        assert_eq!(
            document.verify_offline(
                &policy,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                public_key_hash,
                &fixture_binding(),
            ),
            Err(NitroError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_missing_mismatched_and_all_zero_required_pcrs_or_expired_binding() {
        let (encoded, _, _) = build_fixture();
        let document = NitroAttestationDocument::parse(&encoded).expect("fixture parses");
        let missing = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([(4, fixture_pcr(4))]).expect("policy"),
        );
        assert_eq!(
            document.verify_offline(
                &missing,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                [0; 32],
                &fixture_binding(),
            ),
            Err(NitroError::MissingRequiredPcr)
        );

        let mismatched = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([(0, fixture_pcr(9))]).expect("policy"),
        );
        assert_eq!(
            document.verify_offline(
                &mismatched,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                [0; 32],
                &fixture_binding(),
            ),
            Err(NitroError::PcrMismatch)
        );

        assert_eq!(
            NitroPcrPolicy::new([(0, [0; NITRO_SHA384_PCR_BYTES])]),
            Err(NitroError::PcrPolicyInvalid)
        );
        let mut all_zero = document.clone();
        all_zero.pcrs.insert(0, [0; NITRO_SHA384_PCR_BYTES]);
        let exact = NitroAttestationPolicy::new(
            NitroPcrPolicy::new([(0, fixture_pcr(1))]).expect("policy"),
        );
        assert_eq!(
            all_zero.verify_offline(
                &exact,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                [0; 32],
                &fixture_binding(),
            ),
            Err(NitroError::AllZeroRequiredPcr)
        );

        let mut future = document.clone();
        future.timestamp_ms = NOW_MS + MAX_FUTURE_SKEW_MS + 1;
        assert_eq!(
            future.verify_offline(
                &exact,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                [0; 32],
                &fixture_binding(),
            ),
            Err(NitroError::TimestampFuture)
        );
        let mut stale = document.clone();
        stale.timestamp_ms = NOW_MS - MAX_AGE_MS - 1;
        assert_eq!(
            stale.verify_offline(
                &exact,
                &AcceptingTrustBoundary,
                NOW_MS,
                &[9, 8, 7],
                [0; 32],
                &fixture_binding(),
            ),
            Err(NitroError::TimestampExpired)
        );
        assert_eq!(
            document.verify_release_binding(&fixture_binding(), NOW_MS + 60_001),
            Err(NitroError::ReleaseBindingExpired)
        );
    }

    #[test]
    fn rejects_recipient_plaintext_and_wrong_algorithm() {
        assert_eq!(
            NitroKmsRecipientRequest::from_wire(Vec::new(), "RSAES_OAEP_SHA_256"),
            Err(NitroError::RecipientAttestationMissing)
        );
        assert_eq!(
            NitroKmsRecipientRequest::from_wire(vec![1], "RSAES_OAEP_SHA_1"),
            Err(NitroError::RecipientAlgorithmUnsupported)
        );
        assert_eq!(
            NitroKmsRecipientRequest::from_wire(
                vec![0; MAX_NITRO_ATTESTATION_BYTES + 1],
                "RSAES_OAEP_SHA_256",
            ),
            Err(NitroError::InputTooLarge)
        );
        assert_eq!(
            validate_raw_recipient_response(Some(&[1]), None),
            Err(NitroError::RecipientPlaintextRejected)
        );
        assert_eq!(
            validate_raw_recipient_response(Some(&[1]), Some(&[2])),
            Err(NitroError::RecipientPlaintextRejected)
        );
        assert!(validate_raw_recipient_response(Some(&[]), Some(&[1])).is_ok());
        assert_eq!(
            validate_raw_recipient_response(None, None),
            Err(NitroError::RecipientCiphertextInvalid)
        );
        assert_eq!(
            NitroKmsRecipientResponse::from_ciphertext_for_recipient(Vec::new()),
            Err(NitroError::RecipientCiphertextInvalid)
        );
        assert_eq!(
            NitroKmsRecipientResponse::from_ciphertext_for_recipient(vec![0; 6_145],),
            Err(NitroError::RecipientCiphertextInvalid)
        );
        assert!(NitroKmsRecipientResponse::from_ciphertext_for_recipient(vec![0; 6_143]).is_ok());
        assert!(NitroKmsRecipientResponse::from_ciphertext_for_recipient(vec![0; 6_144]).is_ok());
        assert!(NitroKmsRecipientResponse::from_ciphertext_for_recipient(vec![1, 2, 3]).is_ok());
    }

    #[test]
    fn release_binding_is_deterministic_and_rejects_trailing_data() {
        let binding = fixture_binding();
        let encoded = binding.encode().expect("encode");
        assert_eq!(
            NitroReleaseBinding::decode(&encoded).expect("decode"),
            binding
        );
        assert!(matches!(
            NitroReleaseBinding::decode(&[encoded.as_slice(), &[0]].concat()),
            Err(NitroError::ReleaseBindingMalformed)
        ));
        assert_eq!(
            binding.digest().expect("digest"),
            binding.digest().expect("digest")
        );
    }

    #[test]
    fn rejects_zero_operation_digest() {
        assert_eq!(
            NitroReleaseBinding::new(
                [0; 32],
                "KMS_RELEASE",
                [2; 32],
                7,
                [3; 32],
                NOW_MS + 60_000,
                [4; 32],
            ),
            Err(NitroError::ReleaseBindingMalformed)
        );
    }

    #[test]
    fn rejects_zero_kms_key_identifier_hash() {
        assert_eq!(
            NitroReleaseBinding::new(
                [1; 32],
                "KMS_RELEASE",
                [0; 32],
                7,
                [3; 32],
                NOW_MS + 60_000,
                [4; 32],
            ),
            Err(NitroError::ReleaseBindingMalformed)
        );
    }

    #[test]
    fn rejects_zero_policy_digest() {
        assert_eq!(
            NitroReleaseBinding::new(
                [1; 32],
                "KMS_RELEASE",
                [2; 32],
                7,
                [0; 32],
                NOW_MS + 60_000,
                [4; 32],
            ),
            Err(NitroError::ReleaseBindingMalformed)
        );
    }

    #[test]
    fn rejects_zero_replay_identity() {
        assert_eq!(
            NitroReleaseBinding::new(
                [1; 32],
                "KMS_RELEASE",
                [2; 32],
                7,
                [3; 32],
                NOW_MS + 60_000,
                [0; 32],
            ),
            Err(NitroError::ReleaseBindingMalformed)
        );
    }

    #[test]
    fn rejects_malformed_weak_and_unsupported_rsa_recipient_keys() {
        assert_eq!(
            validate_recipient_public_key(&rsa_spki_with_key_bits(&[0x30, 0x00], &[0x05, 0x00])),
            Err(NitroError::InvalidRecipientPublicKey)
        );

        let valid_modulus = fixture_rsa_modulus();
        assert_eq!(
            validate_recipient_public_key(&rsa_spki(&[], &[1, 0, 1])),
            Err(NitroError::InvalidRecipientPublicKey)
        );
        assert_eq!(
            validate_recipient_public_key(&rsa_spki(&[3], &[1, 0, 1])),
            Err(NitroError::InvalidRecipientPublicKey)
        );
        for exponent in [[0], [1], [2]] {
            assert_eq!(
                validate_recipient_public_key(&rsa_spki(&valid_modulus, &exponent)),
                Err(NitroError::InvalidRecipientPublicKey)
            );
        }

        let public_key = hex::decode(RECIPIENT_PUBLIC_KEY_HEX).expect("recipient key");
        let spki = SubjectPublicKeyInfoOwned::from_der(&public_key).expect("SPKI");
        let key_bits = spki.subject_public_key.as_bytes().expect("key bits");
        assert_eq!(
            validate_recipient_public_key(&rsa_spki_with_key_bits(key_bits, &[0x06, 0x01, 0x2a],)),
            Err(NitroError::InvalidRecipientPublicKey)
        );
        assert!(validate_recipient_public_key(&public_key).is_ok());
    }
}
