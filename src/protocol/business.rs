use serde::{Deserialize, Serialize};
use sha2::Digest;
use crate::{ConclaveResult, enclave::{SignRequest, EnclaveManager}};
use rand::Rng;
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

    /// Generates a signed proof of attribution for a business partner.
    /// This ensures that referrals are cryptographically linked to a valid business identity.
    pub fn generate_attribution(&self, business_id: &str, user_id: &str, metadata: HashMap<String, String>) -> ConclaveResult<BusinessAttribution> {
        if !self.registry.is_active(business_id) {
            return Err(crate::ConclaveError::InvalidPayload);
        }

        let timestamp: u64 = 1710000000; // Mock timestamp
        let ttl: u64 = 3600; // 1 hour TTL
        let expiration: u64 = timestamp + ttl;

        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);

        let mut hasher = sha2::Sha256::new();
        hasher.update(business_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&expiration.to_be_bytes());
        hasher.update(&nonce);

        // Include metadata in hash for integrity
        let mut sorted_metadata: Vec<_> = metadata.iter().collect();
        sorted_metadata.sort_by_key(|a| a.0);
        for (k, v) in sorted_metadata {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }

        let message_hash = hasher.finalize().to_vec();

        let request = SignRequest {
            message_hash,
            derivation_path: format!("m/44'/5757'/0'/0/business/{}", business_id),
            key_id: format!("business_{}", business_id),
            taproot_tweak: None,
        };

        let response = self.enclave.sign(request)?;

        Ok(BusinessAttribution {
            business_id: business_id.to_string(),
            user_id: user_id.to_string(),
            timestamp,
            expiration,
            nonce,
            signature: response.signature_hex,
            metadata,
        })
    }
}
