use der::Decode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(any(test, feature = "development-simulators"))]
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

use crate::{ConclaveError, ConclaveResult};

#[cfg(test)]
pub const MAX_ATTESTATION_AGE_SECS: u64 = 300;
#[cfg(not(test))]
const MAX_ATTESTATION_AGE_SECS: u64 = 300;

#[cfg(test)]
pub const MAX_ATTESTATION_FUTURE_SKEW_SECS: u64 = 30;
#[cfg(not(test))]
const MAX_ATTESTATION_FUTURE_SKEW_SECS: u64 = 30;

/// Version of the canonical signed attestation envelope.
pub const ATTESTATION_ENVELOPE_VERSION: u16 = 2;

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttestationLevel {
    Software,
    TEE,
    StrongBox,
    CloudTEE,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationReportType {
    DeviceIntegrity,
}

/// Purpose bound into attestation evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttestationPurpose {
    Sign,
    Verify,
}

/// Algorithm bound into attestation evidence.
///
/// The current evidence envelope is signed with Ed25519. The other variants
/// are retained as typed policy vocabulary for provider implementations that
/// will be added in a later checkpoint; production policy still requires the
/// exact algorithm declared by its configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttestationAlgorithm {
    Ed25519,
    EcdsaSecp256k1,
    SchnorrSecp256k1,
}

/// Typed extension tokens used by the signed envelope and policy checks.
///
/// Unknown provider tokens are retained as `Opaque` so they remain covered by
/// the signature, but they can never satisfy a production policy requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationExtension {
    PurposeSign,
    PurposeVerify,
    AlgorithmEd25519,
    AlgorithmEcdsaSecp256k1,
    AlgorithmSchnorrSecp256k1,
    HardwareBacked,
    SecureBootEnabled,
    TeeEnabled,
    HardwareRootOfTrust,
    Simulated,
    SimulatedSoftwareOnly,
    PlatformCloud,
    OsVersion(String),
    Opaque(String),
}

impl AttestationExtension {
    fn from_token(token: &str) -> Option<Self> {
        if token.is_empty() || token.contains('|') || token.chars().any(char::is_control) {
            return None;
        }

        Some(match token {
            "PURPOSE_SIGN" => Self::PurposeSign,
            "PURPOSE_VERIFY" => Self::PurposeVerify,
            "ALGORITHM_ED25519" => Self::AlgorithmEd25519,
            "ALGORITHM_EC" | "ALGORITHM_ECDSA_SECP256K1" => Self::AlgorithmEcdsaSecp256k1,
            "ALGORITHM_SCHNORR_SECP256K1" => Self::AlgorithmSchnorrSecp256k1,
            "HARDWARE_BACKED" => Self::HardwareBacked,
            "SECURE_BOOT_ENABLED" => Self::SecureBootEnabled,
            "TEE_ENABLED" => Self::TeeEnabled,
            "HARDWARE_ROOT_OF_TRUST" => Self::HardwareRootOfTrust,
            "SIMULATED" => Self::Simulated,
            "SIMULATED_SOFTWARE_ONLY" => Self::SimulatedSoftwareOnly,
            "PLATFORM_CLOUD" => Self::PlatformCloud,
            value if value.starts_with("OS_VERSION_") && value.len() > "OS_VERSION_".len() => {
                Self::OsVersion(value["OS_VERSION_".len()..].to_string())
            }
            value => Self::Opaque(value.to_string()),
        })
    }

    fn canonical_parts(&self) -> (u8, Option<&str>) {
        match self {
            Self::PurposeSign => (1, None),
            Self::AlgorithmEd25519 => (2, None),
            Self::AlgorithmEcdsaSecp256k1 => (3, None),
            Self::HardwareBacked => (4, None),
            Self::SecureBootEnabled => (5, None),
            Self::TeeEnabled => (6, None),
            Self::HardwareRootOfTrust => (7, None),
            Self::Simulated => (8, None),
            Self::SimulatedSoftwareOnly => (9, None),
            Self::PlatformCloud => (10, None),
            Self::OsVersion(version) => (11, Some(version.as_str())),
            Self::AlgorithmSchnorrSecp256k1 => (12, None),
            Self::PurposeVerify => (13, None),
            Self::Opaque(token) => (255, Some(token.as_str())),
        }
    }

    pub fn purpose(&self) -> Option<AttestationPurpose> {
        match self {
            Self::PurposeSign => Some(AttestationPurpose::Sign),
            Self::PurposeVerify => Some(AttestationPurpose::Verify),
            _ => None,
        }
    }

    pub fn algorithm(&self) -> Option<AttestationAlgorithm> {
        match self {
            Self::AlgorithmEd25519 => Some(AttestationAlgorithm::Ed25519),
            Self::AlgorithmEcdsaSecp256k1 => Some(AttestationAlgorithm::EcdsaSecp256k1),
            Self::AlgorithmSchnorrSecp256k1 => Some(AttestationAlgorithm::SchnorrSecp256k1),
            _ => None,
        }
    }
}

impl From<String> for AttestationExtension {
    fn from(token: String) -> Self {
        Self::from_token(&token).unwrap_or(Self::Opaque(token))
    }
}

impl From<&str> for AttestationExtension {
    fn from(token: &str) -> Self {
        Self::from_token(token).unwrap_or_else(|| Self::Opaque(token.to_string()))
    }
}

pub(crate) fn parse_extension_data(data: &str) -> Option<Vec<AttestationExtension>> {
    if data.is_empty() {
        return None;
    }

    data.split('|')
        .map(AttestationExtension::from_token)
        .collect()
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    let length = u32::try_from(value.len()).ok()?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Some(())
}

fn level_tag(level: AttestationLevel) -> u8 {
    match level {
        AttestationLevel::Software => 0,
        AttestationLevel::TEE => 1,
        AttestationLevel::StrongBox => 2,
        AttestationLevel::CloudTEE => 3,
    }
}

/// Status of the provider-specific verifier behind an attestation policy.
///
/// `Unavailable` is the only production status in this release. Real Android,
/// Nitro, DCAP, and SEV verification are intentionally not simulated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderVerifierStatus {
    Unavailable,
    #[cfg(test)]
    TestOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderVerifier {
    Unavailable,
    #[cfg(test)]
    TestFixture {
        trusted_roots: Vec<String>,
        leaf_public_key: [u8; 32],
    },
}

/// Verification policy for attestation evidence.
///
/// Production policy configuration cannot install arbitrary string trust roots.
/// Until a provider-specific verifier is implemented, production verification
/// remains unavailable and fails closed.
///
/// Compatibility note: the former public string-root builder was intentionally
/// removed. A future provider implementation must expose typed authenticated
/// verifier configuration instead of restoring that API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPolicy {
    allowed_levels: Vec<AttestationLevel>,
    max_age_secs: u64,
    max_future_skew_secs: u64,
    required_purpose: AttestationPurpose,
    required_algorithm: AttestationAlgorithm,
    required_extensions: Vec<AttestationExtension>,
    provider_verifier: ProviderVerifier,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl AttestationPolicy {
    /// Returns the default fail-closed production policy.
    pub fn production() -> Self {
        Self {
            // Generic TEE labels are not sufficient hardware evidence. Real
            // provider verification is still required for these levels too.
            allowed_levels: vec![AttestationLevel::StrongBox, AttestationLevel::CloudTEE],
            max_age_secs: MAX_ATTESTATION_AGE_SECS,
            max_future_skew_secs: MAX_ATTESTATION_FUTURE_SKEW_SECS,
            required_purpose: AttestationPurpose::Sign,
            required_algorithm: AttestationAlgorithm::Ed25519,
            required_extensions: vec![AttestationExtension::PurposeSign],
            provider_verifier: ProviderVerifier::Unavailable,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fixture() -> Self {
        Self {
            allowed_levels: vec![
                AttestationLevel::TEE,
                AttestationLevel::StrongBox,
                AttestationLevel::CloudTEE,
            ],
            max_age_secs: MAX_ATTESTATION_AGE_SECS,
            max_future_skew_secs: MAX_ATTESTATION_FUTURE_SKEW_SECS,
            required_purpose: AttestationPurpose::Sign,
            required_algorithm: AttestationAlgorithm::Ed25519,
            required_extensions: vec![AttestationExtension::PurposeSign],
            provider_verifier: ProviderVerifier::TestFixture {
                trusted_roots: vec![
                    "CONCLAVE_ROOT_CA_V1".to_string(),
                    "CONCLAVE_CLOUD_ROOT_CA_V1".to_string(),
                    "GOOGLE_STRONGBOX_ROOT_V1".to_string(),
                    "AWS_NITRO_ROOT_V1".to_string(),
                ],
                leaf_public_key: test_signing_key().verifying_key().to_bytes(),
            },
        }
    }

    /// Returns a policy restricted to the supplied hardware-backed levels.
    pub fn with_allowed_levels(
        mut self,
        allowed_levels: Vec<AttestationLevel>,
    ) -> ConclaveResult<Self> {
        if allowed_levels.is_empty() || allowed_levels.contains(&AttestationLevel::Software) {
            return Err(ConclaveError::Unsupported(
                "software-only attestation cannot satisfy production policy".to_string(),
            ));
        }

        self.allowed_levels = allowed_levels;
        Ok(self)
    }

    /// Returns a policy using explicit freshness limits.
    pub fn with_freshness_window(
        mut self,
        max_age_secs: u64,
        max_future_skew_secs: u64,
    ) -> ConclaveResult<Self> {
        if max_age_secs > MAX_ATTESTATION_AGE_SECS
            || max_future_skew_secs > MAX_ATTESTATION_FUTURE_SKEW_SECS
        {
            return Err(ConclaveError::Unsupported(
                "attestation freshness limits cannot be weaker than production defaults"
                    .to_string(),
            ));
        }

        self.max_age_secs = max_age_secs;
        self.max_future_skew_secs = max_future_skew_secs;
        Ok(self)
    }

    /// Compatibility wrapper for the former string-root configuration API.
    ///
    /// Production builds deliberately reject arbitrary roots because a string
    /// label is not an authenticated provider verifier. Unit-test builds route
    /// this legacy shape to the explicitly test-only fixture instead.
    pub fn with_trusted_roots(self, trusted_roots: Vec<String>) -> ConclaveResult<Self> {
        #[cfg(test)]
        {
            self.with_test_trusted_roots(trusted_roots)
        }

        #[cfg(not(test))]
        {
            let _ = trusted_roots;
            Err(ConclaveError::Unsupported(
                "arbitrary attestation roots require an unavailable provider verifier".to_string(),
            ))
        }
    }

    pub fn with_required_purpose(mut self, purpose: AttestationPurpose) -> Self {
        self.required_purpose = purpose;
        self.required_extensions
            .retain(|extension| extension.purpose().is_none());
        self.required_extensions.push(match purpose {
            AttestationPurpose::Sign => AttestationExtension::PurposeSign,
            AttestationPurpose::Verify => AttestationExtension::PurposeVerify,
        });
        self
    }

    pub fn with_required_algorithm(mut self, algorithm: AttestationAlgorithm) -> Self {
        self.required_algorithm = algorithm;
        self
    }

    /// Returns a policy requiring exact typed extension tokens in addition to
    /// the mandatory signing-purpose marker.
    pub fn with_required_extensions<T>(
        mut self,
        required_extensions: Vec<T>,
    ) -> ConclaveResult<Self>
    where
        T: Into<AttestationExtension>,
    {
        for extension in required_extensions {
            let extension = extension.into();
            if matches!(&extension, AttestationExtension::Opaque(token) if token.trim().is_empty())
            {
                return Err(ConclaveError::InvalidPayload);
            }
            if !self.required_extensions.contains(&extension) {
                self.required_extensions.push(extension);
            }
        }

        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn with_test_trusted_roots(
        mut self,
        trusted_roots: Vec<String>,
    ) -> ConclaveResult<Self> {
        if trusted_roots.is_empty() || trusted_roots.iter().any(|root| root.trim().is_empty()) {
            return Err(ConclaveError::InvalidPayload);
        }

        self.provider_verifier = ProviderVerifier::TestFixture {
            trusted_roots,
            leaf_public_key: test_signing_key().verifying_key().to_bytes(),
        };
        Ok(self)
    }

    pub fn allowed_levels(&self) -> &[AttestationLevel] {
        &self.allowed_levels
    }

    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    pub fn max_future_skew_secs(&self) -> u64 {
        self.max_future_skew_secs
    }

    pub fn required_purpose(&self) -> AttestationPurpose {
        self.required_purpose
    }

    pub fn required_algorithm(&self) -> AttestationAlgorithm {
        self.required_algorithm
    }

    pub fn required_extensions(&self) -> &[AttestationExtension] {
        &self.required_extensions
    }

    pub fn provider_verifier_status(&self) -> ProviderVerifierStatus {
        match self.provider_verifier {
            ProviderVerifier::Unavailable => ProviderVerifierStatus::Unavailable,
            #[cfg(test)]
            ProviderVerifier::TestFixture { .. } => ProviderVerifierStatus::TestOnly,
        }
    }

    fn is_test_fixture(&self) -> bool {
        #[cfg(test)]
        {
            matches!(self.provider_verifier, ProviderVerifier::TestFixture { .. })
        }

        #[cfg(not(test))]
        {
            false
        }
    }

    fn verify_provider_evidence(&self, _report: &DeviceIntegrityReport) -> bool {
        match &self.provider_verifier {
            ProviderVerifier::Unavailable => false,
            #[cfg(test)]
            ProviderVerifier::TestFixture {
                trusted_roots,
                leaf_public_key,
            } => {
                if !_report.certificate_chain_is_well_formed() {
                    return false;
                }

                let leaf_matches = _report
                    .certificate_chain
                    .first()
                    .and_then(|entry| hex::decode(entry).ok())
                    .and_then(|key| <[u8; 32]>::try_from(key).ok())
                    .is_some_and(|key| key == *leaf_public_key);
                let root_matches = _report
                    .certificate_chain
                    .last()
                    .is_some_and(|root| trusted_roots.iter().any(|trusted| trusted == root));

                leaf_matches && root_matches
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIntegrityReport {
    pub report_version: u16,
    pub report_type: AttestationReportType,
    pub level: AttestationLevel,
    pub challenge_nonce: Vec<u8>,
    pub signature: Vec<u8>,
    /// Public key used for the value-bearing operation. This field is covered
    /// by the attestation-leaf signature and is checked against the provider's
    /// operation signature key at the typed signing boundary.
    pub attested_operation_public_key: Vec<u8>,
    /// Full certificate/identity chain. The first entry is the leaf public key
    /// as hex in the currently supported software/test envelope.
    pub certificate_chain: Vec<String>,
    pub timestamp: u64,
    /// Legacy transport representation retained for compatibility. It is
    /// parsed exactly and signed alongside `extensions`; it is not trusted by
    /// substring matching.
    pub extension_data: String,
    /// Exact typed extension tokens covered by the signed envelope.
    pub extensions: Vec<AttestationExtension>,
}

impl DeviceIntegrityReport {
    /// Verifies the integrity report with the production policy.
    pub fn verify(&self, expected_nonce: &[u8]) -> bool {
        self.verify_with_policy(expected_nonce, &AttestationPolicy::production())
    }

    /// Verifies this report against an explicit fail-closed policy.
    pub fn verify_with_policy(&self, expected_nonce: &[u8], policy: &AttestationPolicy) -> bool {
        self.verify_at_time_impl(expected_nonce, unix_time_secs(), policy)
    }

    /// Verifies at a specific timestamp using the internal test-only fixture
    /// policy. This convenience method is not available to downstream users.
    #[cfg(test)]
    pub fn verify_at_time(&self, expected_nonce: &[u8], now_secs: u64) -> bool {
        self.verify_at_time_with_policy(
            expected_nonce,
            now_secs,
            &AttestationPolicy::test_fixture(),
        )
    }

    /// Verifies at a caller-supplied timestamp using an explicit policy.
    ///
    /// Production callers should use [`Self::verify_with_policy`], which
    /// samples the wall clock once. This crate-visible variant lets protocol
    /// code share that exact timestamp with related checks and lets tests
    /// exercise freshness boundaries without sampling the wall clock twice.
    pub(crate) fn verify_at_time_with_policy(
        &self,
        expected_nonce: &[u8],
        now_secs: u64,
        policy: &AttestationPolicy,
    ) -> bool {
        self.verify_at_time_impl(expected_nonce, now_secs, policy)
    }

    fn verify_at_time_impl(
        &self,
        expected_nonce: &[u8],
        now_secs: u64,
        policy: &AttestationPolicy,
    ) -> bool {
        if self.signature.is_empty()
            || self.attested_operation_public_key.is_empty()
            || self.attested_operation_public_key.len() > 65
            || !self.certificate_chain_is_well_formed()
        {
            return false;
        }

        // The canonical envelope rejects missing/unknown versions, malformed
        // typed extensions, and any field mismatch before cryptographic use.
        let canonical = match self.canonical_signed_bytes() {
            Some(canonical) => canonical,
            None => return false,
        };

        if self.challenge_nonce != expected_nonce {
            return false;
        }

        let is_fresh = if self.timestamp > now_secs {
            self.timestamp
                .checked_sub(now_secs)
                .is_some_and(|future_skew| future_skew <= policy.max_future_skew_secs)
        } else {
            now_secs
                .checked_sub(self.timestamp)
                .is_some_and(|age| age <= policy.max_age_secs)
        };
        if !is_fresh {
            return false;
        }

        if !self.verify_signature(&canonical) {
            return false;
        }

        // This is the provider-verifier boundary. There is deliberately no
        // generic DER subject parser or string-root fallback in production.
        if !policy.verify_provider_evidence(self) {
            return false;
        }

        if !policy.allowed_levels.contains(&self.level) {
            return false;
        }

        if policy
            .required_extensions
            .iter()
            .any(|required| !self.extensions.contains(required))
        {
            return false;
        }

        let is_hardened = match self.level {
            AttestationLevel::StrongBox | AttestationLevel::CloudTEE => {
                self.extensions
                    .contains(&AttestationExtension::HardwareBacked)
                    && self
                        .extensions
                        .contains(&AttestationExtension::SecureBootEnabled)
            }
            // Generic TEE is accepted only by the crate-internal test fixture;
            // the default production policy excludes it and has no verifier.
            AttestationLevel::TEE => policy.is_test_fixture(),
            AttestationLevel::Software => false,
        };

        let purposes = self
            .extensions
            .iter()
            .filter_map(AttestationExtension::purpose)
            .collect::<Vec<_>>();
        let algorithms = self
            .extensions
            .iter()
            .filter_map(AttestationExtension::algorithm)
            .collect::<Vec<_>>();
        let has_expected_purpose =
            purposes.len() == 1 && purposes.first().copied() == Some(policy.required_purpose);
        let has_expected_algorithm =
            algorithms.len() == 1 && algorithms.first().copied() == Some(policy.required_algorithm);

        is_hardened && has_expected_purpose && has_expected_algorithm
    }

    fn canonical_signed_bytes(&self) -> Option<Vec<u8>> {
        if self.report_version != ATTESTATION_ENVELOPE_VERSION
            || self.report_type != AttestationReportType::DeviceIntegrity
            || self.certificate_chain.is_empty()
        {
            return None;
        }

        let parsed_extensions = parse_extension_data(&self.extension_data)?;
        if parsed_extensions != self.extensions {
            return None;
        }

        let mut output = Vec::new();
        output.extend_from_slice(b"CONXIAN-ATTESTATION-ENVELOPE\0");
        output.extend_from_slice(&self.report_version.to_be_bytes());
        output.push(1); // DeviceIntegrity report type
        output.push(level_tag(self.level));
        append_len_prefixed(&mut output, &self.challenge_nonce)?;
        append_len_prefixed(&mut output, &self.attested_operation_public_key)?;
        output.extend_from_slice(&self.timestamp.to_be_bytes());

        let extension_count = u32::try_from(self.extensions.len()).ok()?;
        output.extend_from_slice(&extension_count.to_be_bytes());
        for extension in &self.extensions {
            let (tag, value) = extension.canonical_parts();
            output.push(tag);
            append_len_prefixed(&mut output, value.unwrap_or_default().as_bytes())?;
        }

        // Include the exact legacy field too, so every serialized report field
        // remains covered even when a caller mutates representation details.
        append_len_prefixed(&mut output, self.extension_data.as_bytes())?;

        let chain_count = u32::try_from(self.certificate_chain.len()).ok()?;
        output.extend_from_slice(&chain_count.to_be_bytes());
        for chain_entry in &self.certificate_chain {
            append_len_prefixed(&mut output, chain_entry.as_bytes())?;
        }

        Some(output)
    }

    fn certificate_chain_is_well_formed(&self) -> bool {
        if self.certificate_chain.len() < 2
            || self.certificate_chain.iter().any(|entry| entry.is_empty())
        {
            return false;
        }

        let leaf = match self
            .certificate_chain
            .first()
            .and_then(|entry| hex::decode(entry).ok())
        {
            Some(leaf) => leaf,
            None => return false,
        };
        if leaf.len() != 32 {
            return false;
        }

        if self.certificate_chain.len() > 2 {
            for intermediate in &self.certificate_chain[1..self.certificate_chain.len() - 1] {
                let der = match hex::decode(intermediate) {
                    Ok(der) => der,
                    Err(_) => return false,
                };
                if Certificate::from_der(&der).is_err() {
                    return false;
                }
            }
        }

        true
    }

    fn verify_signature(&self, canonical: &[u8]) -> bool {
        let raw_pubkey = match self
            .certificate_chain
            .first()
            .and_then(|entry| hex::decode(entry).ok())
        {
            Some(raw_pubkey) if raw_pubkey.len() == 32 => raw_pubkey,
            _ => return false,
        };

        let bytes: [u8; 32] = match raw_pubkey.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&bytes) {
            Ok(verifying_key) => verifying_key,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&self.signature) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        verifying_key.verify(canonical, &signature).is_ok()
    }

    #[cfg(any(test, feature = "development-simulators"))]
    pub(crate) fn sign_with_ed25519_key(&mut self, signing_key: &SigningKey) -> ConclaveResult<()> {
        let canonical = self
            .canonical_signed_bytes()
            .ok_or(ConclaveError::InvalidPayload)?;
        self.signature = signing_key.sign(&canonical).to_bytes().to_vec();
        Ok(())
    }

    /// Generates a hardware-bound fingerprint for this device identity.
    pub fn get_device_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for cert in &self.certificate_chain {
            hasher.update(cert.as_bytes());
        }
        hasher.update(&self.attested_operation_public_key);
        for extension in &self.extensions {
            let (tag, value) = extension.canonical_parts();
            hasher.update([tag]);
            if let Some(value) = value {
                hasher.update(value.as_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
pub(crate) fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

#[cfg(test)]
mod tests {
    use super::{
        parse_extension_data, test_signing_key, AttestationExtension, AttestationLevel,
        AttestationPolicy, AttestationReportType, DeviceIntegrityReport, MAX_ATTESTATION_AGE_SECS,
    };
    use ed25519_dalek::SigningKey;

    fn valid_report(timestamp: u64, level: AttestationLevel) -> DeviceIntegrityReport {
        let signing_key = test_signing_key();
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let nonce = vec![1, 2, 3, 4];
        let mut extension_data = "PURPOSE_SIGN|ALGORITHM_ED25519|OS_VERSION_14".to_string();
        if level == AttestationLevel::StrongBox || level == AttestationLevel::CloudTEE {
            extension_data.push_str("|HARDWARE_BACKED|SECURE_BOOT_ENABLED");
        }
        let extensions = parse_extension_data(&extension_data).expect("valid extensions");

        let mut report = DeviceIntegrityReport {
            report_version: super::ATTESTATION_ENVELOPE_VERSION,
            report_type: AttestationReportType::DeviceIntegrity,
            level,
            challenge_nonce: nonce,
            signature: Vec::new(),
            attested_operation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            certificate_chain: vec![pubkey_hex, "CONCLAVE_ROOT_CA_V1".to_string()],
            timestamp,
            extension_data,
            extensions,
        };
        report
            .sign_with_ed25519_key(&signing_key)
            .expect("fixture should sign");
        report
    }

    #[test]
    fn verify_accepts_report_within_freshness_window() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);

        assert!(report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_accepts_strongbox_report() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60), AttestationLevel::StrongBox);

        assert!(report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn production_policy_rejects_generic_tee_and_is_unavailable() {
        let now_secs: u64 = 1_000_000;
        let report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        let policy = AttestationPolicy::production();

        assert!(!report.verify_at_time_with_policy(&[1, 2, 3, 4], now_secs, &policy));
        assert_eq!(
            policy.provider_verifier_status(),
            super::ProviderVerifierStatus::Unavailable
        );
        assert!(!policy.allowed_levels().contains(&AttestationLevel::TEE));
    }

    #[test]
    fn typed_policy_rejects_wrong_purpose_and_algorithm() {
        let now_secs: u64 = 1_000_000;
        let signing_key = test_signing_key();

        let mut wrong_purpose = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        wrong_purpose.extension_data = "PURPOSE_VERIFY|ALGORITHM_ED25519|OS_VERSION_14".to_string();
        wrong_purpose.extensions =
            parse_extension_data(&wrong_purpose.extension_data).expect("valid extensions");
        wrong_purpose
            .sign_with_ed25519_key(&signing_key)
            .expect("fixture should sign");
        assert!(!wrong_purpose.verify_at_time(&[1, 2, 3, 4], now_secs));

        let mut wrong_algorithm = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        wrong_algorithm.extension_data =
            "PURPOSE_SIGN|ALGORITHM_ECDSA_SECP256K1|OS_VERSION_14".to_string();
        wrong_algorithm.extensions =
            parse_extension_data(&wrong_algorithm.extension_data).expect("valid extensions");
        wrong_algorithm
            .sign_with_ed25519_key(&signing_key)
            .expect("fixture should sign");
        assert!(!wrong_algorithm.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_stale_report() {
        let now_secs: u64 = 1_000_000;
        let stale_timestamp = now_secs.saturating_sub(MAX_ATTESTATION_AGE_SECS + 1);
        let report = valid_report(stale_timestamp, AttestationLevel::TEE);

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.signature[0] ^= 0xFF;

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn verify_rejects_untrusted_root() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.certificate_chain[1] = "UNKNOWN_ROOT".to_string();

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn attacker_key_with_trusted_label_is_rejected() {
        let now_secs: u64 = 1_000_000;
        let attacker_key = SigningKey::from_bytes(&[0x24; 32]);
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.certificate_chain[0] = hex::encode(attacker_key.verifying_key().to_bytes());
        report
            .sign_with_ed25519_key(&attacker_key)
            .expect("attacker can sign its forged envelope");

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn changing_signed_security_fields_invalidates_report() {
        let now_secs: u64 = 1_000_000;

        let mut level_changed = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        level_changed.level = AttestationLevel::StrongBox;
        assert!(!level_changed.verify_at_time(&[1, 2, 3, 4], now_secs));

        let mut extension_changed =
            valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        extension_changed.extensions[0] = AttestationExtension::HardwareBacked;
        assert!(!extension_changed.verify_at_time(&[1, 2, 3, 4], now_secs));

        let mut leaf_changed = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        leaf_changed.certificate_chain[0] = hex::encode([0x11; 32]);
        assert!(!leaf_changed.verify_at_time(&[1, 2, 3, 4], now_secs));

        let mut chain_changed = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        chain_changed
            .certificate_chain
            .push("SWAPPED_CHAIN_ENTRY".to_string());
        assert!(!chain_changed.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn malformed_certificate_chain_is_rejected() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.certificate_chain.insert(1, String::new());

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn extension_matching_is_exact_not_substring_based() {
        let now_secs: u64 = 1_000_000;
        let signing_key = test_signing_key();
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::StrongBox);
        report.extension_data =
            "PURPOSE_SIGNED|ALGORITHM_ED25519|HARDWARE_BACKED_EXTRA|SECURE_BOOT_ENABLED_EXTRA"
                .to_string();
        report.extensions = parse_extension_data(&report.extension_data).expect("opaque tokens");
        report
            .sign_with_ed25519_key(&signing_key)
            .expect("fixture should sign");

        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }

    #[test]
    fn report_type_and_version_are_signed() {
        let now_secs: u64 = 1_000_000;
        let mut report = valid_report(now_secs.saturating_sub(60), AttestationLevel::TEE);
        report.report_version = 99;
        assert!(!report.verify_at_time(&[1, 2, 3, 4], now_secs));
    }
}
