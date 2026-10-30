//! Digital license terms and zero-manual-onboarding verification.
//!
//! This module lets external developers run sovereign Conxian nodes without a
//! manual onboarding round-trip. A node embeds only the issuer's Ed25519
//! public key and verifies a self-contained license (or API key) offline.
//! Licenses carry capability grants and seat limits, and can be bound to an
//! optional opaque bearer API key via a SHA-256 fingerprint.

use crate::{ConclaveError, ConclaveResult};
use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A named capability a license may grant (for example `"relay"`, `"settle"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Capability(pub String);

impl Capability {
    /// Creates a capability from any string-like value.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the capability name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Capability {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// The signed claims of a digital license — everything that is signed except
/// the signature itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub license_id: String,
    pub holder: String,
    pub issuer: String,
    pub capabilities: Vec<Capability>,
    /// Maximum number of concurrently held seats. `0` means the license is
    /// not seat-gated (unlimited concurrent use).
    pub seat_limit: u32,
    /// Unix timestamp (seconds) at which the license was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) at which the license expires. `0` means the
    /// license never expires.
    pub expires_at: u64,
    /// Optional SHA-256 fingerprint (lowercase hex) of a separate opaque
    /// bearer API key this license is bound to.
    pub api_key_fingerprint: Option<String>,
}

impl LicenseClaims {
    /// Deterministic byte encoding used for both signing and verification.
    pub fn canonical_bytes(&self) -> ConclaveResult<Vec<u8>> {
        let mut claims = self.clone();
        claims.capabilities.sort();
        serde_json::to_vec(&claims).map_err(|err| {
            ConclaveError::CryptoError(format!("license canonicalization failed: {err}"))
        })
    }
}

/// A signed digital license.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigitalLicense {
    pub claims: LicenseClaims,
    /// Lowercase hex-encoded Ed25519 signature over `claims.canonical_bytes()`.
    pub signature: String,
}

impl DigitalLicense {
    /// Returns the license identifier from the signed claims.
    pub fn license_id(&self) -> &str {
        &self.claims.license_id
    }

    /// Returns `true` if the license grants `capability`.
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.claims.capabilities.contains(capability)
    }
}

/// Mints [`DigitalLicense`] values and self-contained API keys.
pub struct LicenseIssuer {
    signing_key: SigningKey,
    issuer: String,
}

impl LicenseIssuer {
    /// Creates an issuer deterministically from a 32-byte seed.
    pub fn from_seed(issuer: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            issuer: issuer.into(),
        }
    }

    /// Creates an issuer from a freshly generated random key.
    pub fn generate(issuer: impl Into<String>) -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self::from_seed(issuer, seed)
    }

    /// Returns the issuer identifier stamped into issued licenses.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Hex-encoded Ed25519 public key that verifiers must trust.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs `claims` into a [`DigitalLicense`], stamping the issuer.
    pub fn issue(&self, mut claims: LicenseClaims) -> ConclaveResult<DigitalLicense> {
        claims.issuer = self.issuer.clone();
        let canonical = claims.canonical_bytes()?;
        let signature = self.signing_key.sign(&canonical);
        Ok(DigitalLicense {
            claims,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    /// Mints a self-contained API key: a base64url-encoded JSON license.
    ///
    /// A client verifies the returned key offline using only the issuer's
    /// public key, so a sovereign node can be stood up with zero manual
    /// onboarding round-trip.
    pub fn mint_api_key(&self, claims: LicenseClaims) -> ConclaveResult<String> {
        let license = self.issue(claims)?;
        let json = serde_json::to_vec(&license)
            .map_err(|err| ConclaveError::CryptoError(format!("license encoding failed: {err}")))?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(json))
    }
}

/// Verifies digital licenses and self-contained API keys offline.
#[derive(Debug, Clone)]
pub struct LicenseVerifier {
    verifying_key: VerifyingKey,
    issuer: String,
}

impl LicenseVerifier {
    /// Builds a verifier from a hex-encoded Ed25519 public key.
    pub fn from_public_key_hex(
        issuer: impl Into<String>,
        public_key_hex: &str,
    ) -> ConclaveResult<Self> {
        let bytes = hex::decode(public_key_hex).map_err(|_| ConclaveError::InvalidPayload)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| ConclaveError::InvalidPayload)?;
        Ok(Self {
            verifying_key,
            issuer: issuer.into(),
        })
    }

    /// Returns the trusted issuer identifier this verifier enforces.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verifies the Ed25519 signature, issuer binding, and temporal validity
    /// of `license` at wall-clock time `now`.
    pub fn verify_at(&self, license: &DigitalLicense, now: u64) -> ConclaveResult<()> {
        if license.claims.issuer != self.issuer {
            return Err(ConclaveError::CryptoError(
                "license issuer does not match the trusted issuer".to_string(),
            ));
        }

        if license.claims.issued_at > now {
            return Err(ConclaveError::CryptoError(
                "license is not yet valid".to_string(),
            ));
        }

        if license.claims.expires_at != 0 && license.claims.expires_at <= now {
            return Err(ConclaveError::CryptoError(
                "license has expired".to_string(),
            ));
        }

        let signature_bytes =
            hex::decode(&license.signature).map_err(|_| ConclaveError::InvalidPayload)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ConclaveError::InvalidPayload)?;
        let canonical = license.claims.canonical_bytes()?;

        self.verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| {
                ConclaveError::CryptoError("license signature verification failed".to_string())
            })
    }

    /// Verifies a license at the current wall-clock time.
    pub fn verify(&self, license: &DigitalLicense) -> ConclaveResult<()> {
        self.verify_at(license, unix_time_secs())
    }

    /// Verifies a self-contained API key and returns the decoded license.
    pub fn verify_api_key_at(&self, api_key: &str, now: u64) -> ConclaveResult<DigitalLicense> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(api_key)
            .map_err(|_| ConclaveError::InvalidPayload)?;
        let license: DigitalLicense =
            serde_json::from_slice(&bytes).map_err(|_| ConclaveError::InvalidPayload)?;
        self.verify_at(&license, now)?;
        Ok(license)
    }

    /// Verifies a self-contained API key at the current wall-clock time.
    pub fn verify_api_key(&self, api_key: &str) -> ConclaveResult<DigitalLicense> {
        self.verify_api_key_at(api_key, unix_time_secs())
    }

    /// Returns `true` if `license` grants `capability`.
    pub fn has_capability(&self, license: &DigitalLicense, capability: &Capability) -> bool {
        license.has_capability(capability)
    }
}

/// Tracks concurrent seat allocation across verified licenses.
#[derive(Debug, Default)]
pub struct SeatRegistry {
    seats: RwLock<HashMap<String, BTreeSet<String>>>,
}

impl SeatRegistry {
    /// Creates an empty seat registry.
    pub fn new() -> Self {
        Self {
            seats: RwLock::new(HashMap::new()),
        }
    }

    /// Attempts to acquire a seat for `license`. Fails when the license has
    /// reached its `seat_limit` or the seat is already held.
    pub fn try_acquire(
        &self,
        license: &DigitalLicense,
        seat_id: impl Into<String>,
    ) -> ConclaveResult<()> {
        let seat_id = seat_id.into();
        let mut seats = self
            .seats
            .write()
            .map_err(|_| ConclaveError::CryptoError("seat registry lock poisoned".to_string()))?;

        let held = seats.entry(license.license_id().to_string()).or_default();
        if held.contains(&seat_id) {
            return Err(ConclaveError::CryptoError(
                "seat is already allocated".to_string(),
            ));
        }

        let limit = license.claims.seat_limit;
        if limit != 0 && held.len() as u32 >= limit {
            return Err(ConclaveError::CryptoError(
                "license seat limit reached".to_string(),
            ));
        }

        held.insert(seat_id);
        Ok(())
    }

    /// Releases a previously acquired seat, returning whether it was held.
    pub fn release(&self, license_id: &str, seat_id: &str) -> bool {
        let Ok(mut seats) = self.seats.write() else {
            return false;
        };
        let Some(held) = seats.get_mut(license_id) else {
            return false;
        };
        let removed = held.remove(seat_id);
        if held.is_empty() {
            seats.remove(license_id);
        }
        removed
    }

    /// Returns the number of currently held seats for a license.
    pub fn allocated_seats(&self, license_id: &str) -> usize {
        self.seats
            .read()
            .ok()
            .and_then(|seats| seats.get(license_id).map(BTreeSet::len))
            .unwrap_or(0)
    }
}

/// Computes the SHA-256 fingerprint of an opaque bearer API key as lowercase hex.
pub fn api_key_fingerprint(api_key: &str) -> String {
    hex::encode(Sha256::digest(api_key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "conxian-labs";
    const SEED: [u8; 32] = [0x5a; 32];

    fn test_issuer() -> LicenseIssuer {
        LicenseIssuer::from_seed(ISSUER, SEED)
    }

    fn test_verifier() -> LicenseVerifier {
        LicenseVerifier::from_public_key_hex(ISSUER, &test_issuer().public_key_hex()).unwrap()
    }

    fn base_claims(now: u64) -> LicenseClaims {
        LicenseClaims {
            license_id: "lic-001".to_string(),
            holder: "acme-corp".to_string(),
            issuer: ISSUER.to_string(),
            capabilities: vec![Capability::new("relay"), Capability::new("settle")],
            seat_limit: 2,
            issued_at: now,
            expires_at: now + 3600,
            api_key_fingerprint: None,
        }
    }

    #[test]
    fn license_roundtrip_verifies() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        test_verifier().verify_at(&license, now + 1)?;
        Ok(())
    }

    #[test]
    fn tampered_claims_are_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let mut license = test_issuer().issue(base_claims(now))?;
        license.claims.seat_limit = 99;
        assert!(test_verifier().verify_at(&license, now + 1).is_err());
        Ok(())
    }

    #[test]
    fn wrong_issuer_key_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        let other_verifier = LicenseVerifier::from_public_key_hex(
            ISSUER,
            &LicenseIssuer::from_seed(ISSUER, [0x6b; 32]).public_key_hex(),
        )
        .unwrap();
        assert!(other_verifier.verify_at(&license, now + 1).is_err());
        Ok(())
    }

    #[test]
    fn issuer_name_mismatch_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        let wrong_issuer =
            LicenseVerifier::from_public_key_hex("other-issuer", &test_issuer().public_key_hex())
                .unwrap();
        assert!(wrong_issuer.verify_at(&license, now + 1).is_err());
        Ok(())
    }

    #[test]
    fn expired_license_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        assert!(test_verifier().verify_at(&license, now + 3601).is_err());
        Ok(())
    }

    #[test]
    fn not_yet_valid_license_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        assert!(test_verifier().verify_at(&license, now - 1).is_err());
        Ok(())
    }

    #[test]
    fn perpetual_license_stays_valid() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let mut claims = base_claims(now);
        claims.expires_at = 0;
        let license = test_issuer().issue(claims)?;
        test_verifier().verify_at(&license, now + 86_400 * 365)?;
        Ok(())
    }

    #[test]
    fn api_key_roundtrip_recovers_claims() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let claims = base_claims(now);
        let api_key = test_issuer().mint_api_key(claims.clone())?;
        let recovered = test_verifier().verify_api_key_at(&api_key, now + 1)?;
        assert_eq!(recovered.claims.license_id, claims.license_id);
        assert_eq!(recovered.claims.holder, claims.holder);
        Ok(())
    }

    #[test]
    fn tampered_api_key_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let api_key = test_issuer().mint_api_key(base_claims(now))?;
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(&api_key).unwrap();
        let mut tampered = bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xff;
        let tampered_key = BASE64_URL_SAFE_NO_PAD.encode(&tampered);
        assert!(test_verifier()
            .verify_api_key_at(&tampered_key, now + 1)
            .is_err());
        Ok(())
    }

    #[test]
    fn capability_gating_reflects_grants() {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now)).unwrap();
        let verifier = test_verifier();
        assert!(verifier.has_capability(&license, &Capability::new("relay")));
        assert!(verifier.has_capability(&license, &Capability::new("settle")));
        assert!(!verifier.has_capability(&license, &Capability::new("rwa")));
    }

    #[test]
    fn seat_allocation_enforces_limit() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        let registry = SeatRegistry::new();

        registry.try_acquire(&license, "seat-a")?;
        registry.try_acquire(&license, "seat-b")?;
        assert!(registry.try_acquire(&license, "seat-c").is_err());
        assert_eq!(registry.allocated_seats(license.license_id()), 2);
        Ok(())
    }

    #[test]
    fn seat_release_frees_capacity() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        let registry = SeatRegistry::new();

        registry.try_acquire(&license, "seat-a")?;
        registry.try_acquire(&license, "seat-b")?;
        assert!(registry.release(license.license_id(), "seat-a"));
        registry.try_acquire(&license, "seat-c")?;
        assert_eq!(registry.allocated_seats(license.license_id()), 2);
        Ok(())
    }

    #[test]
    fn duplicate_seat_is_rejected() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let license = test_issuer().issue(base_claims(now))?;
        let registry = SeatRegistry::new();

        registry.try_acquire(&license, "seat-a")?;
        assert!(registry.try_acquire(&license, "seat-a").is_err());
        Ok(())
    }

    #[test]
    fn unlimited_seat_limit_never_rejects() -> ConclaveResult<()> {
        let now = 1_700_000_000;
        let mut claims = base_claims(now);
        claims.seat_limit = 0;
        let license = test_issuer().issue(claims)?;
        let registry = SeatRegistry::new();

        for i in 0..50 {
            registry.try_acquire(&license, format!("seat-{i}"))?;
        }
        assert_eq!(registry.allocated_seats(license.license_id()), 50);
        Ok(())
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        assert_eq!(api_key_fingerprint("abc"), api_key_fingerprint("abc"));
        assert_ne!(api_key_fingerprint("abc"), api_key_fingerprint("abd"));
    }
}
