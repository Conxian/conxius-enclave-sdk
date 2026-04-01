use crate::{
    ConclaveError, ConclaveResult,
    enclave::{EnclaveManager, SignRequest},
};
use rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessAttribution {
    pub business_id: String,
    pub user_id: String,
    pub timestamp: u64,
    pub expiration: u64,
    pub nonce: [u8; 16],
    pub signature: String,
    pub metadata: HashMap<String, String>,
}

impl BusinessAttribution {
    /// Hashes the attribution data for signing or verification.
    pub fn get_hash(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.business_id.as_bytes());
        hasher.update(self.user_id.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.expiration.to_be_bytes());
        hasher.update(self.nonce);

        // Include metadata in hash for integrity
        let mut sorted_metadata: Vec<_> = self.metadata.iter().collect();
        sorted_metadata.sort_by_key(|a| a.0);
        for (k, v) in sorted_metadata {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }

        hasher.finalize().to_vec()
    }

    /// Verifies the cryptographic signature of the attribution against a public key.
    pub fn verify(&self, public_key_hex: &str) -> ConclaveResult<()> {
        let secp = Secp256k1::new();
        let hash = self.get_hash();

        let message_bytes: [u8; 32] = hash
            .try_into()
            .map_err(|_| ConclaveError::CryptoError("Invalid hash length".to_string()))?;
        let message = Message::from_digest(message_bytes);

        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|_| ConclaveError::CryptoError("Invalid public key hex".to_string()))?;
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|_| ConclaveError::CryptoError("Invalid public key format".to_string()))?;

        let signature_bytes = hex::decode(&self.signature)
            .map_err(|_| ConclaveError::CryptoError("Invalid signature hex".to_string()))?;

        // Handle both DER and Compact formats for maximum compatibility
        let signature = Signature::from_compact(&signature_bytes)
            .or_else(|_| Signature::from_der(&signature_bytes))
            .map_err(|_| ConclaveError::CryptoError("Invalid signature format".to_string()))?;

        if secp.verify_ecdsa(message, &signature, &public_key).is_ok() {
            Ok(())
        } else {
            Err(ConclaveError::CryptoError(
                "Business attribution signature verification failed".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessProfile {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub active: bool,
}

#[derive(Clone)]
pub struct BusinessRegistry {
    businesses: HashMap<String, BusinessProfile>,
}

impl Default for BusinessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BusinessRegistry {
    pub fn new() -> Self {
        Self {
            businesses: HashMap::new(),
        }
    }

    pub fn register_business(&mut self, profile: BusinessProfile) {
        self.businesses.insert(profile.id.clone(), profile);
    }

    pub fn get_business(&self, id: &str) -> Option<&BusinessProfile> {
        self.businesses.get(id)
    }

    pub fn is_active(&self, id: &str) -> bool {
        self.businesses.get(id).map(|b| b.active).unwrap_or(false)
    }
}

pub struct BusinessManager<'a> {
    enclave: &'a dyn EnclaveManager,
    registry: BusinessRegistry,
}

impl<'a> BusinessManager<'a> {
    pub fn new(enclave: &'a dyn EnclaveManager, registry: BusinessRegistry) -> Self {
        Self { enclave, registry }
    }

    /// Generates a new hardware-backed business identity.
    pub fn generate_business_identity(
        &self,
        business_id: &str,
        name: &str,
    ) -> ConclaveResult<BusinessProfile> {
        let public_key = self
            .enclave
            .get_public_key(&format!("m/44'/5757'/0'/0/business/{}", business_id))?;

        Ok(BusinessProfile {
            id: business_id.to_string(),
            name: name.to_string(),
            public_key,
            active: true,
        })
    }

    /// Generates a signed proof of attribution for a business partner.
    /// This ensures that referrals are cryptographically linked to a valid business identity.
    pub fn generate_attribution(
        &self,
        business_id: &str,
        user_id: &str,
        metadata: HashMap<String, String>,
    ) -> ConclaveResult<BusinessAttribution> {
        if !self.registry.is_active(business_id) {
            return Err(ConclaveError::InvalidPayload);
        }

        let timestamp: u64 = 1710000000; // Mock timestamp
        let ttl: u64 = 3600; // 1 hour TTL
        let expiration: u64 = timestamp + ttl;

        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);

        let mut attribution = BusinessAttribution {
            business_id: business_id.to_string(),
            user_id: user_id.to_string(),
            timestamp,
            expiration,
            nonce,
            signature: String::new(),
            metadata,
        };

        let message_hash = attribution.get_hash();

        let request = SignRequest {
            message_hash,
            derivation_path: format!("m/44'/5757'/0'/0/business/{}", business_id),
            key_id: format!("business_{}", business_id),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;
        attribution.signature = response.signature_hex;

        Ok(attribution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_attribution_verification() {
        let enclave = CloudEnclave {
            kms_endpoint: "test".to_string(),
        };
        let mut registry = BusinessRegistry::new();

        // Get the mock public key from the cloud enclave
        let public_key = enclave
            .get_public_key("m/44'/5757'/0'/0/business/partner_01")
            .unwrap();

        // Register a business
        let profile = BusinessProfile {
            id: "partner_01".to_string(),
            name: "Partner 1".to_string(),
            public_key: public_key.clone(),
            active: true,
        };
        registry.register_business(profile.clone());

        let mgr = BusinessManager::new(&enclave, registry);
        let attribution = mgr
            .generate_attribution("partner_01", "user_123", HashMap::new())
            .unwrap();

        // Verify the signature using the profile's public key
        let res = attribution.verify(&profile.public_key);
        assert!(res.is_ok(), "Verification failed: {:?}", res.err());
    }
}
