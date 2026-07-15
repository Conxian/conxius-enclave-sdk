use crate::protocol::bitcoin::TaprootManager;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;
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
}
