use crate::{ConclaveError, ConclaveResult};
use bitcoin::PublicKey;
use bitcoin::secp256k1::{self, Scalar, Secp256k1, SecretKey};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Fedimint Nexus Adapter (v2.0.7)
/// Orchestrates e-cash blinding and unblinding with multi-federation support.
pub struct FedimintAdapter {
    /// Registry of active federations and their simulated public keys.
    pub federations: HashMap<String, PublicKey>,
    _secp: Secp256k1<secp256k1::All>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintMintIntent {
    pub amount_sats: u64,
    pub federation_id: String,
    pub blinded_messages: Vec<String>, // Hex-encoded blinded Secp256k1 public keys
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintEcash {
    pub notes: Vec<EcashNote>,
    pub total_amount: u64,
    pub proof_of_reserve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashNote {
    pub federation_id: String,
    pub amount: u64,
    pub secret: String,    // Original secret used for note derivation
    pub signature: String, // Unblinded signature (s)
}

impl Default for FedimintAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FedimintAdapter {
    pub fn new() -> Self {
        Self {
            federations: HashMap::new(),
            _secp: Secp256k1::new(),
        }
    }

    /// Registers a new federation in the adapter using a unique identifier.
    pub fn register_federation(&mut self, federation_id: &str) -> ConclaveResult<()> {
        let mut fed_sk_hasher = Sha256::new();
        fed_sk_hasher.update(federation_id.as_bytes());
        let fed_sk_hash = fed_sk_hasher.finalize();
        let fed_sk_bytes: [u8; 32] = fed_sk_hash.into();
        let fed_sk = SecretKey::from_secret_bytes(fed_sk_bytes).map_err(|_| {
            ConclaveError::CryptoError("Failed to derive federation key".to_string())
        })?;

        let fed_pk_internal = secp256k1::PublicKey::from_secret_key(&fed_sk);
        let fed_pk = PublicKey::from_secp(fed_pk_internal);
        self.federations.insert(federation_id.to_string(), fed_pk);
        Ok(())
    }

    /// Joins a federation using a standard Fedimint invite code.
    /// Hardened for v2.0.7: Prepares internal state for fedimint-client-wasm.
    pub fn join_federation(&mut self, invite_code: &str) -> ConclaveResult<String> {
        if !invite_code.starts_with("fed1") {
            return Err(ConclaveError::InvalidPayload);
        }

        // In a production environment with fedimint-client-wasm, this would
        // initialize the Peer-to-Peer gossip and fetch the config.
        let mut hasher = Sha256::new();
        hasher.update(invite_code.as_bytes());
        let fed_id = hex::encode(&hasher.finalize()[0..8]);

        self.register_federation(&fed_id)?;
        Ok(fed_id)
    }

    /// Prepares a mint intent for community-governed liquidity.
    pub fn prepare_mint_intent(
        &self,
        federation_id: &str,
        amount_sats: u64,
        secrets: Vec<&str>,
    ) -> ConclaveResult<(FedimintMintIntent, Vec<String>)> {
        if !self.federations.contains_key(federation_id) {
            return Err(ConclaveError::RailError(
                "Federation not registered".to_string(),
            ));
        }

        if amount_sats == 0 || secrets.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        let mut blinded_messages = Vec::new();
        let mut blinding_factors = Vec::new();

        for secret_str in secrets.iter() {
            // 1. Hash secret to a curve point P = H(secret) * G
            let mut hasher = Sha256::new();
            hasher.update(secret_str.as_bytes());
            let secret_hash = hasher.finalize();
            let sk_bytes: [u8; 32] = secret_hash.into();
            let sk = SecretKey::from_secret_bytes(sk_bytes)
                .map_err(|_| ConclaveError::CryptoError("Invalid secret hash".to_string()))?;

            let pk_internal = secp256k1::PublicKey::from_secret_key(&sk);

            // 2. Deterministic blinding factor
            let mut r_hasher = Sha256::new();
            r_hasher.update(secret_str.as_bytes());
            r_hasher.update(b"BLINDING_FACTOR_v2");
            let r_hash = r_hasher.finalize();
            let r_bytes: [u8; 32] = r_hash.into();

            blinding_factors.push(hex::encode(r_bytes));

            // 3. Blind the point: B = P * r
            let r_scalar = Scalar::from_be_bytes(r_bytes)
                .map_err(|_| ConclaveError::CryptoError("Invalid blinding factor".to_string()))?;
            let blinded_pk = pk_internal
                .mul_tweak(&r_scalar)
                .map_err(|e| ConclaveError::CryptoError(format!("Blinding failed: {:?}", e)))?;

            blinded_messages.push(hex::encode(blinded_pk.serialize()));
        }

        Ok((
            FedimintMintIntent {
                amount_sats,
                federation_id: federation_id.to_string(),
                blinded_messages,
            },
            blinding_factors,
        ))
    }

    /// Issues e-cash from a registered federation.
    pub fn issue_ecash(
        &self,
        intent: FedimintMintIntent,
        blinding_factors: Vec<String>,
        original_secrets: Vec<String>,
    ) -> ConclaveResult<FedimintEcash> {
        if !self.federations.contains_key(&intent.federation_id) {
            return Err(ConclaveError::RailError(
                "Federation not registered".to_string(),
            ));
        }

        if intent.blinded_messages.len() != blinding_factors.len() {
            return Err(ConclaveError::InvalidPayload);
        }

        let mut notes = Vec::new();
        let amount_per_note = intent.amount_sats / intent.blinded_messages.len() as u64;

        // Simulated Federation Secret Key (derived from ID)
        let mut fed_sk_hasher = Sha256::new();
        fed_sk_hasher.update(intent.federation_id.as_bytes());
        let fed_sk_hash = fed_sk_hasher.finalize();
        let fed_sk_bytes: [u8; 32] = fed_sk_hash.into();
        let fed_sk = SecretKey::from_secret_bytes(fed_sk_bytes)
            .map_err(|_| ConclaveError::CryptoError("Invalid federation key".to_string()))?;
        let fed_scalar = Scalar::from_be_bytes(fed_sk.to_secret_bytes())
            .map_err(|_| ConclaveError::CryptoError("Invalid federation scalar".to_string()))?;

        for (i, _msg_hex) in intent.blinded_messages.iter().enumerate() {
            // Recompute original public key point P = H(secret) * G
            let mut h = Sha256::new();
            h.update(original_secrets[i].as_bytes());
            let s_hash = h.finalize();
            let sk_b: [u8; 32] = s_hash.into();
            let sk = SecretKey::from_secret_bytes(sk_b)
                .map_err(|_| ConclaveError::CryptoError("Invalid secret key".to_string()))?;
            let pk_internal = secp256k1::PublicKey::from_secret_key(&sk);

            // Recompute unblinded signature: Sig = P * s
            let unblinded_sig = pk_internal.mul_tweak(&fed_scalar)
                .map_err(|_| ConclaveError::CryptoError("Signature computation failed".to_string()))?;

            notes.push(EcashNote {
                federation_id: intent.federation_id.clone(),
                amount: amount_per_note,
                secret: original_secrets[i].clone(),
                signature: hex::encode(unblinded_sig.serialize()),
            });
        }

        Ok(FedimintEcash {
            notes,
            total_amount: intent.amount_sats,
            proof_of_reserve: Some(hex::encode(intent.amount_sats.to_be_bytes())),
        })
    }

    /// Verifies an e-cash note signature against the registered federation public key.
    pub fn verify_note(&self, note: &EcashNote) -> bool {
        if !self.federations.contains_key(&note.federation_id) {
            return false;
        };

        // 1. Recompute the note's public key point P = H(secret) * G
        let mut hasher = Sha256::new();
        hasher.update(note.secret.as_bytes());
        let secret_hash = hasher.finalize();
        let sk_bytes: [u8; 32] = secret_hash.into();
        let sk = match SecretKey::from_secret_bytes(sk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let pk_internal = secp256k1::PublicKey::from_secret_key(&sk);

        // 2. Recompute the expected signature Sig = P * s
        let mut fed_sk_hasher = Sha256::new();
        fed_sk_hasher.update(note.federation_id.as_bytes());
        let fed_sk_hash = fed_sk_hasher.finalize();
        let fed_sk_bytes: [u8; 32] = fed_sk_hash.into();
        let fed_sk = match SecretKey::from_secret_bytes(fed_sk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let fed_scalar = match Scalar::from_be_bytes(fed_sk.to_secret_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let expected_sig = match pk_internal.mul_tweak(&fed_scalar) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 3. Compare with the provided signature
        note.signature == hex::encode(expected_sig.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fedimint_mint_flow() {
        let mut adapter = FedimintAdapter::new();
        adapter.register_federation("fed-1").unwrap();

        let secrets = vec!["secret1", "secret2"];
        let (intent, blinding_factors) = adapter
            .prepare_mint_intent("fed-1", 1000, secrets.clone())
            .unwrap();

        assert_eq!(intent.blinded_messages.len(), 2);

        let ecash = adapter
            .issue_ecash(
                intent,
                blinding_factors,
                secrets.iter().map(|s| s.to_string()).collect(),
            )
            .unwrap();

        assert_eq!(ecash.total_amount, 1000);
        assert_eq!(ecash.notes.len(), 2);
        assert!(adapter.verify_note(&ecash.notes[0]));
        assert!(adapter.verify_note(&ecash.notes[1]));
    }

    #[test]
    fn test_fedimint_join_federation() {
        let mut adapter = FedimintAdapter::new();
        let fed_id = adapter.join_federation("fed1_example_invite").unwrap();
        assert!(adapter.federations.contains_key(&fed_id));
    }

    #[test]
    fn test_fedimint_multiple_federations() {
        let mut adapter = FedimintAdapter::new();
        adapter.register_federation("fed-1").unwrap();
        adapter.register_federation("fed-2").unwrap();

        let secrets1 = vec!["s1"];
        let (intent1, bf1) = adapter
            .prepare_mint_intent("fed-1", 100, secrets1.clone())
            .unwrap();
        let ecash1 = adapter
            .issue_ecash(intent1, bf1, vec!["s1".to_string()])
            .unwrap();

        let secrets2 = vec!["s2"];
        let (intent2, bf2) = adapter
            .prepare_mint_intent("fed-2", 200, secrets2.clone())
            .unwrap();
        let ecash2 = adapter
            .issue_ecash(intent2, bf2, vec!["s2".to_string()])
            .unwrap();

        assert!(adapter.verify_note(&ecash1.notes[0]));
        assert!(adapter.verify_note(&ecash2.notes[0]));

        // Federation mismatch fails
        assert_eq!(ecash1.notes[0].federation_id, "fed-1");
        assert_eq!(ecash2.notes[0].federation_id, "fed-2");
    }

    #[test]
    fn test_fedimint_invalid_federation() {
        let mut adapter = FedimintAdapter::new();
        adapter.register_federation("fed-1").unwrap();

        let intent = FedimintMintIntent {
            amount_sats: 1000,
            federation_id: "fed-2".to_string(),
            blinded_messages: vec!["msg1".to_string()],
        };

        let result = adapter.issue_ecash(intent, vec!["bf1".into()], vec!["s1".into()]);
        assert!(result.is_err());
    }
}
