use crate::{protocol_unsupported, ConclaveResult, UnsupportedOperation, UnsupportedProtocol};
use serde::{Deserialize, Serialize};

/// FROST (Flexible Round-Optimized Schnorr Threshold Signatures) API boundary.
///
/// Value-bearing FROST operations remain explicitly unsupported until an audited
/// RFC 9591 implementation and conformance vectors are available.
pub struct FrostManager;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostKeyPackage {
    pub min_signers: u32,
    pub total_signers: u32,
    pub identifier: String,
    pub group_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostSignatureShare {
    pub signer_id: u32,
    pub share: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostDkgRound1Package {
    pub signer_id: u32,
    pub commitments: Vec<String>, // Hex-encoded commitments to polynomial coefficients
    pub proof_of_knowledge: String, // Schnorr signature as PoK of secret key
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostDkgRound2Package {
    pub signer_id: u32,
    pub encrypted_shares: Vec<FrostEncryptedShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrostEncryptedShare {
    pub receiver_id: u32,
    pub encrypted_share: String, // Hex-encoded encrypted share
}

impl FrostManager {
    /// Generates a FROST key package.
    pub fn generate_key_package(
        _min_signers: u32,
        _total_signers: u32,
        _identifier: &str,
    ) -> ConclaveResult<FrostKeyPackage> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::KeyPackageGeneration,
        ))
    }

    /// Performs Round 1 of FROST DKG.
    pub fn generate_dkg_round1(
        &self,
        _signer_id: u32,
        _threshold: u32,
    ) -> ConclaveResult<FrostDkgRound1Package> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    /// Verifies the DKG Round 1 proof of knowledge.
    pub fn verify_dkg_round1(&self, _package: &FrostDkgRound1Package) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    /// Performs Round 2 of FROST DKG.
    pub fn generate_dkg_round2(
        &self,
        _signer_id: u32,
        _other_signer_ids: Vec<u32>,
        _round1_package: &FrostDkgRound1Package,
    ) -> ConclaveResult<FrostDkgRound2Package> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    /// Verifies a received encrypted share against the sender's commitments.
    pub fn verify_received_share(
        &self,
        _receiver_id: u32,
        _round1_package: &FrostDkgRound1Package,
        _round2_package: &FrostDkgRound2Package,
    ) -> ConclaveResult<bool> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::Dkg,
        ))
    }

    /// Aggregates signature shares into a standard Schnorr signature.
    pub fn aggregate_signatures(
        &self,
        _package: &FrostKeyPackage,
        _shares: Vec<FrostSignatureShare>,
        _message: &[u8],
    ) -> ConclaveResult<String> {
        Err(protocol_unsupported(
            UnsupportedProtocol::Frost,
            UnsupportedOperation::ThresholdSigning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConclaveError;

    #[test]
    fn test_frost_operations_are_explicitly_unsupported() {
        let mgr = FrostManager;
        let round1 = FrostDkgRound1Package {
            signer_id: 1,
            commitments: vec!["commitment".to_string()],
            proof_of_knowledge: "proof".to_string(),
        };
        let round2 = FrostDkgRound2Package {
            signer_id: 1,
            encrypted_shares: vec![FrostEncryptedShare {
                receiver_id: 2,
                encrypted_share: "share".to_string(),
            }],
        };
        let package = FrostKeyPackage {
            min_signers: 2,
            total_signers: 3,
            identifier: "vault-1".to_string(),
            group_public_key: "group_pk".to_string(),
        };

        assert_unsupported(
            FrostManager::generate_key_package(2, 3, "vault-1"),
            UnsupportedOperation::KeyPackageGeneration,
        );
        assert_unsupported(mgr.generate_dkg_round1(1, 2), UnsupportedOperation::Dkg);
        assert_unsupported(mgr.verify_dkg_round1(&round1), UnsupportedOperation::Dkg);
        assert_unsupported(
            mgr.generate_dkg_round2(1, vec![2], &round1),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            mgr.verify_received_share(2, &round1, &round2),
            UnsupportedOperation::Dkg,
        );
        assert_unsupported(
            mgr.aggregate_signatures(&package, Vec::new(), b"message"),
            UnsupportedOperation::ThresholdSigning,
        );
    }

    fn assert_unsupported<T>(result: ConclaveResult<T>, operation: UnsupportedOperation) {
        match result {
            Err(ConclaveError::ProtocolUnsupported {
                protocol: UnsupportedProtocol::Frost,
                operation: actual_operation,
                reason: crate::UnsupportedReason::NoAuditedImplementation,
            }) => assert_eq!(actual_operation, operation),
            _ => panic!("expected typed FROST unsupported error"),
        }
    }
}
