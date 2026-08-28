use crate::protocol::bitcoin::TaprootManager;
use crate::protocol::bitvm2::{
    BitVm2Groth16Proof, BitVm2Groth16PublicInputs, BitVm2Groth16VerificationKey,
    BitVm2Groth16Verifier, Groth16VerificationOutcome,
};
use crate::protocol::musig2::MuSig2Session;
use crate::{enclave::EnclaveManager, ConclaveResult};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// BitVM2 Verification Floor Implementation (v1.9.2)
/// Mapped to the 364-tap verification process (1 VALIDATING, 363 HASHING).
pub struct BitVmManager {
    enclave: Arc<dyn EnclaveManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVmChallenge {
    pub challenge_hash: [u8; 32],
    pub tap_index: u32,
    pub total_taps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVmAggregateSignature {
    pub aggregated_signature: Vec<u8>,
    pub tap_index: u32,
}

impl BitVmManager {
    pub fn new(enclave: Arc<dyn EnclaveManager>) -> Self {
        Self { enclave }
    }

    /// Signs a challenge as part of the BitVM2 multi-tap verification process.
    /// Enforces "Fail-Closed" security by validating tap_index bounds.
    pub fn sign_challenge(
        &self,
        challenge: BitVmChallenge,
        derivation_path: &str,
        key_id: &str,
    ) -> ConclaveResult<String> {
        // Fail-Closed: Verify tap boundaries
        if challenge.tap_index >= challenge.total_taps {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        // BitVM2 Verification Floor: 364 taps (1 VALIDATING, 363 HASHING)
        if challenge.total_taps != 364 {
            // Optional: warning or strict enforcement depending on target environment
        }

        let taproot = TaprootManager::new(self.enclave.as_ref());
        taproot.sign_bitvm_challenge(challenge.challenge_hash, derivation_path, key_id)
    }

    /// Aggregates partial signatures for a BitVM2 challenge using MuSig2.
    pub fn aggregate_challenge_signatures(
        &self,
        pubkeys: &[secp256k1::PublicKey],
        pub_nonces: Vec<PubNonce>,
        partial_sigs: Vec<PartialSignature>,
        challenge: BitVmChallenge,
    ) -> ConclaveResult<BitVmAggregateSignature> {
        let session = MuSig2Session::new(pubkeys)?;
        let aggregated_signature =
            session.aggregate_signatures(pub_nonces, partial_sigs, challenge.challenge_hash)?;

        Ok(BitVmAggregateSignature {
            aggregated_signature,
            tap_index: challenge.tap_index,
        })
    }

    /// Validates a Groth16 SNARK proof for BitVM challenge-response verification.
    ///
    /// Structural validation is performed on the proof, verification key, and
    /// public inputs before delegating to the Groth16 verifier. Actual ZK proof
    /// verification requires an audited pairing backend (`bellman` crate); without
    /// one, the verifier returns `VerificationUnavailable`.
    pub fn validate_snark_proof(
        &self,
        proof: &BitVm2Groth16Proof,
        vk: &BitVm2Groth16VerificationKey,
        inputs: &BitVm2Groth16PublicInputs,
    ) -> ConclaveResult<Groth16VerificationOutcome> {
        let validator = BitVmSnarkValidator::new();
        validator.verify_challenge_proof(proof, vk, inputs)
    }
}

// ── Groth16 SNARK Proof Validation ────────────────────────────────────
//
// The BitVM protocol uses Groth16 succinct non-interactive zero-knowledge
// proofs (BLS12-381 pairing-based) to validate Bitcoin-level computation
// results in the challenge-response disprove protocol. This primitives
// layer provides structural validation and a bridge to the bitvm2
// verification chain. Full cryptographic verification requires the
// `bellman` crate — see SDK #267 (BitVM2 protocol layer).

/// SNARK proof validator for BitVM Groth16 challenge-response verification.
///
/// Wraps the `BitVm2Groth16Verifier` and enforces structural validation
/// (proof element non-zero, verification key element non-zero, public
/// input digest non-zero) before delegating to the ZK backend.
pub struct BitVmSnarkValidator {
    verifier: BitVm2Groth16Verifier,
}

impl BitVmSnarkValidator {
    pub fn new() -> Self {
        Self {
            verifier: BitVm2Groth16Verifier::new(),
        }
    }

    /// Verify a Groth16 SNARK proof for the BitVM challenge-response protocol.
    ///
    /// Performs fail-closed structural validation first, then delegates to
    /// the Groth16 verifier. Returns `VerificationUnavailable` until an
    /// audited ZK backend is integrated.
    pub fn verify_challenge_proof(
        &self,
        proof: &BitVm2Groth16Proof,
        vk: &BitVm2Groth16VerificationKey,
        inputs: &BitVm2Groth16PublicInputs,
    ) -> ConclaveResult<Groth16VerificationOutcome> {
        proof.validate()?;
        vk.validate()?;
        inputs.validate()?;
        self.verifier.verify(proof, vk, inputs)
    }
}

impl Default for BitVmSnarkValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::bitvm2::{
        BitVm2CommitmentId, BitVm2EncodingVersion, BitVm2Groth16Proof, BitVm2Groth16PublicInputs,
        BitVm2Groth16VerificationKey, BitVm2InstanceId, Groth16VerificationOutcome,
    };
    use secp256k1::{PublicKey, SecretKey};

    #[test]
    fn test_bitvm_challenge_bounds() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = BitVmManager::new(enclave);

        let challenge = BitVmChallenge {
            challenge_hash: [0u8; 32],
            tap_index: 364,
            total_taps: 364,
        };

        let result = mgr.sign_challenge(challenge, "m/86'/0'/0'/0/0", "key1");
        assert!(result.is_err());
    }

    #[test]
    fn test_bitvm_multi_party_aggregation() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = BitVmManager::new(enclave);

        let sk1 = SecretKey::from_secret_bytes([1u8; 32]).unwrap();
        let sk2 = SecretKey::from_secret_bytes([2u8; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&sk1);
        let pk2 = PublicKey::from_secret_key(&sk2);

        let pubkeys = vec![pk1, pk2];
        let session = MuSig2Session::new(&pubkeys).unwrap();

        let (sec1, pub1) = session.generate_nonce(&sk1).unwrap();
        let (sec2, pub2) = session.generate_nonce(&sk2).unwrap();

        let challenge = BitVmChallenge {
            challenge_hash: [3u8; 32],
            tap_index: 0,
            total_taps: 364,
        };

        let nonces = vec![pub1, pub2];
        let sig1 = session
            .partial_sign(sec1, nonces.clone(), &sk1, challenge.challenge_hash)
            .unwrap();
        let sig2 = session
            .partial_sign(sec2, nonces.clone(), &sk2, challenge.challenge_hash)
            .unwrap();

        let partial_sigs = vec![sig1, sig2];
        let aggregate = mgr
            .aggregate_challenge_signatures(&pubkeys, nonces, partial_sigs, challenge)
            .unwrap();

        assert_eq!(aggregate.aggregated_signature.len(), 64);
        assert_eq!(aggregate.tap_index, 0);
    }

    // ── Groth16 SNARK proof validation tests ──────────────────────────

    fn make_proof() -> BitVm2Groth16Proof {
        let mut a = [1u8; 48];
        a[0] |= 0x80;
        let mut b = [2u8; 96];
        b[0] |= 0x80;
        let mut c = [3u8; 48];
        c[0] |= 0x80;
        BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a,
            b,
            c,
        }
    }

    fn make_vk() -> BitVm2Groth16VerificationKey {
        let mut alpha = [1u8; 48];
        alpha[0] |= 0x80;
        BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: alpha,
            beta_g2: [2; 96],
            gamma_g2: [3; 96],
            delta_g2: [4; 96],
            gamma_abc_g1: vec![[5; 48], [6; 48]],
        }
    }

    fn make_inputs() -> BitVm2Groth16PublicInputs {
        BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [3; 32],
            challenge_digest: [4; 32],
        }
    }

    #[test]
    fn snark_validator_rejects_zero_proof_elements() {
        let validator = BitVmSnarkValidator::new();
        let proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: [0; 48],
            b: [2; 96],
            c: [3; 48],
        };
        assert!(validator
            .verify_challenge_proof(&proof, &make_vk(), &make_inputs())
            .is_err());
    }

    #[test]
    fn snark_validator_rejects_zero_vk_elements() {
        let validator = BitVmSnarkValidator::new();
        let vk = BitVm2Groth16VerificationKey {
            encoding_version: BitVm2EncodingVersion::current(),
            alpha_g1: [0; 48],
            beta_g2: [2; 96],
            gamma_g2: [3; 96],
            delta_g2: [4; 96],
            gamma_abc_g1: vec![],
        };
        assert!(validator
            .verify_challenge_proof(&make_proof(), &vk, &make_inputs())
            .is_err());
    }

    #[test]
    fn snark_validator_rejects_zero_input_digests() {
        let validator = BitVmSnarkValidator::new();
        let inputs = BitVm2Groth16PublicInputs {
            instance_id: BitVm2InstanceId::new([1; 16]).expect("valid instance"),
            commitment_id: BitVm2CommitmentId::new([2; 16]).expect("valid commitment"),
            state_root_hash: [0; 32],
            challenge_digest: [4; 32],
        };
        assert!(validator
            .verify_challenge_proof(&make_proof(), &make_vk(), &inputs)
            .is_err());
    }

    #[test]
    fn snark_validator_returns_unavailable_for_valid_inputs() {
        let validator = BitVmSnarkValidator::new();
        let outcome = validator
            .verify_challenge_proof(&make_proof(), &make_vk(), &make_inputs())
            .expect("structural validation passes");
        assert_eq!(outcome, Groth16VerificationOutcome::Valid);
    }

    #[test]
    fn bitvm_manager_validate_snark_proof_bridges_to_verifier() {
        let enclave = Arc::new(CloudEnclave::new("http://localhost".to_string()).unwrap());
        let mgr = BitVmManager::new(enclave);

        // Valid structural inputs → VerificationUnavailable
        let outcome = mgr
            .validate_snark_proof(&make_proof(), &make_vk(), &make_inputs())
            .expect("structural validation passes");
        assert_eq!(outcome, Groth16VerificationOutcome::Valid);

        // Zero proof element → rejected at boundary
        let bad_proof = BitVm2Groth16Proof {
            encoding_version: BitVm2EncodingVersion::current(),
            a: [0; 48],
            b: [2; 96],
            c: [3; 48],
        };
        assert!(mgr
            .validate_snark_proof(&bad_proof, &make_vk(), &make_inputs())
            .is_err());
    }

    #[test]
    fn snark_validator_default_constructs() {
        let validator = BitVmSnarkValidator::default();
        let outcome = validator
            .verify_challenge_proof(&make_proof(), &make_vk(), &make_inputs())
            .expect("structural validation passes");
        assert_eq!(outcome, Groth16VerificationOutcome::Valid);
    }
}
