//! FROST threshold signing integration (SDK-002).
//!
//! Bridges the real ZF FROST v3.0.0 crypto backend
//! (`src/protocol/frost_crypto.rs`) into the signing module.
//!
//! # SDK-002
//! See `docs/PHASE1_ISSUES_ROADMAP.md` for acceptance criteria.

use crate::ConclaveResult;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Threshold signing interface for FROST DKG and signature operations.
pub trait ThresholdSigner {
    /// Run DKG round 1: generate secret and round-1 packages.
    fn dkg_round1(
        &self,
        participant_id: &[u8],
        max_signers: u16,
        min_signers: u16,
    ) -> ConclaveResult<(Vec<u8>, Vec<u8>)>;

    /// Run DKG round 2: process round-1 packages from all participants.
    fn dkg_round2(
        &self,
        secret_bytes: &[u8],
        round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ConclaveResult<(Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)>;

    /// Run DKG round 3: finalize key generation.
    fn dkg_round3(
        &self,
        round2_secret_bytes: &[u8],
        round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
        round2_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ConclaveResult<(Vec<u8>, Vec<u8>)>;

    /// Generate nonces and commitments for a signing session.
    fn create_nonces(&self, key_package: &[u8]) -> ConclaveResult<(Vec<u8>, Vec<u8>)>;

    /// Create a signing package from message and commitment list.
    fn create_signing_package(
        &self,
        message: &[u8],
        commitments: &[Vec<u8>],
    ) -> ConclaveResult<Vec<u8>>;

    /// Create a signature share.
    fn create_signature_share(
        &self,
        key_package: &[u8],
        nonces: &[u8],
        signing_package: &[u8],
        message: &[u8],
    ) -> ConclaveResult<Vec<u8>>;

    /// Aggregate signature shares into a final Schnorr signature.
    fn aggregate(
        &self,
        signing_package: &[u8],
        shares: &[(u16, Vec<u8>)],
        verifying_key: &[u8],
    ) -> ConclaveResult<String>;
}

// ---------------------------------------------------------------------------
// ZF FROST v3.0.0 backend
// ---------------------------------------------------------------------------

/// Threshold signer backed by the ZF FROST v3.0.0 secp256k1 implementation.
pub struct FrostThresholdSigner;

impl FrostThresholdSigner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FrostThresholdSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl ThresholdSigner for FrostThresholdSigner {
    fn dkg_round1(
        &self,
        participant_id: &[u8],
        max_signers: u16,
        min_signers: u16,
    ) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::dkg_part1(participant_id, max_signers, min_signers)
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (participant_id, max_signers, min_signers);
            Err(crate::ConclaveError::Unsupported(
                "FROST DKG requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn dkg_round2(
        &self,
        secret_bytes: &[u8],
        round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ConclaveResult<(Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::dkg_part2(secret_bytes, round1_packages)
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (secret_bytes, round1_packages);
            Err(crate::ConclaveError::Unsupported(
                "FROST DKG requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn dkg_round3(
        &self,
        round2_secret_bytes: &[u8],
        round1_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
        round2_packages: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::dkg_part3(
                round2_secret_bytes,
                round1_packages,
                round2_packages,
            )
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (round2_secret_bytes, round1_packages, round2_packages);
            Err(crate::ConclaveError::Unsupported(
                "FROST DKG requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn create_nonces(&self, key_package: &[u8]) -> ConclaveResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::create_nonces_and_commitments(key_package)
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = key_package;
            Err(crate::ConclaveError::Unsupported(
                "FROST signing requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn create_signing_package(
        &self,
        message: &[u8],
        commitments: &[Vec<u8>],
    ) -> ConclaveResult<Vec<u8>> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::create_signing_package(message, commitments)
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (message, commitments);
            Err(crate::ConclaveError::Unsupported(
                "FROST signing requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn create_signature_share(
        &self,
        key_package: &[u8],
        nonces: &[u8],
        signing_package: &[u8],
        message: &[u8],
    ) -> ConclaveResult<Vec<u8>> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::create_signature_share(
                key_package,
                nonces,
                signing_package,
                message,
            )
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (key_package, nonces, signing_package, message);
            Err(crate::ConclaveError::Unsupported(
                "FROST signing requires the frost-crypto feature".to_string(),
            ))
        }
    }

    fn aggregate(
        &self,
        signing_package: &[u8],
        shares: &[(u16, Vec<u8>)],
        verifying_key: &[u8],
    ) -> ConclaveResult<String> {
        #[cfg(feature = "frost-crypto")]
        {
            crate::protocol::frost_crypto::aggregate(signing_package, shares, verifying_key)
        }
        #[cfg(not(feature = "frost-crypto"))]
        {
            let _ = (signing_package, shares, verifying_key);
            Err(crate::ConclaveError::Unsupported(
                "FROST aggregation requires the frost-crypto feature".to_string(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frost_signer_default_constructs() {
        let signer = FrostThresholdSigner::default();
        assert!(matches!(
            signer.dkg_round1(b"test", 3, 2),
            Err(crate::ConclaveError::Unsupported(_)) | Ok(_)
        ));
    }

    #[test]
    fn frost_signer_is_send_sync() {
        fn _assert(_s: impl Send + Sync) {}
        _assert(FrostThresholdSigner::new());
    }

    #[test]
    fn frost_dkg_rounds_type_check() {
        let signer = FrostThresholdSigner::new();
        // All return types must compile
        let _: ConclaveResult<(Vec<u8>, Vec<u8>)> =
            signer.dkg_round1(b"id", 3, 2);
        let _: ConclaveResult<(Vec<u8>, Vec<u8>)> =
            signer.dkg_round3(b"s", &BTreeMap::new(), &BTreeMap::new());
        let _: ConclaveResult<String> =
            signer.aggregate(b"sp", &[], b"vk");
    }

    #[test]
    fn frost_signing_rounds_type_check() {
        let signer = FrostThresholdSigner::new();
        let _: ConclaveResult<(Vec<u8>, Vec<u8>)> =
            signer.create_nonces(b"kp");
        let _: ConclaveResult<Vec<u8>> =
            signer.create_signing_package(b"msg", &[]);
        let _: ConclaveResult<Vec<u8>> =
            signer.create_signature_share(b"kp", b"nonces", b"sp", b"msg");
    }
}
