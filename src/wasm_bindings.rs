use wasm_bindgen::prelude::*;
use crate::enclave::EnclaveManager;
#[cfg(target_arch = "wasm32")]
use crate::enclave::android_strongbox::AndroidStrongBox;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::asset::{AssetRegistry, AssetIdentifier, AssetMetadata, Chain};
use crate::protocol::business::{BusinessRegistry, BusinessProfile, BusinessManager, BusinessAttribution};
use crate::protocol::rails::RailProxy;
use crate::protocol::fiat::FiatRouterService;
use crate::protocol::a2p::A2pRouterService;
use crate::protocol::mmr::MmrService;
use crate::protocol::job_card::CJCSManager;
use crate::protocol::bitcoin::TaprootManager;
use std::sync::Arc;
use std::collections::HashMap;

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    enclave: Arc<dyn EnclaveManager>,
    assets: Arc<AssetRegistry>,
    businesses: Arc<BusinessRegistry>,
    rails: Arc<RailProxy>,
    fiat: Arc<FiatRouterService>,
    a2p: Arc<A2pRouterService>,
    mmr: Arc<MmrService>,
    http_client: reqwest::Client,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(gateway_url: &str, kms_endpoint: Option<String>) -> Self {
        let http_client = reqwest::Client::new();

        #[cfg(target_arch = "wasm32")]
        let enclave: Arc<dyn EnclaveManager> = if let Some(kms) = kms_endpoint {
            Arc::new(CloudEnclave { kms_endpoint: kms })
        } else {
            Arc::new(AndroidStrongBox::new())
        };

        #[cfg(not(target_arch = "wasm32"))]
        let enclave: Arc<dyn EnclaveManager> = Arc::new(CloudEnclave {
            kms_endpoint: kms_endpoint.unwrap_or_else(|| "https://vault.conxian.io".to_string())
        });

        let assets = Arc::new(AssetRegistry::new());
        let businesses = Arc::new(BusinessRegistry::new());
        let rails = Arc::new(RailProxy::new(gateway_url.to_string(), http_client.clone()));

        let fiat = Arc::new(FiatRouterService::new(gateway_url.to_string(), http_client.clone()));
        let a2p = Arc::new(A2pRouterService::new(gateway_url.to_string(), http_client.clone()));
        let mmr = Arc::new(MmrService::new(gateway_url.to_string(), http_client.clone()));

        Self {
            enclave,
            assets,
            businesses,
            rails,
            fiat,
            a2p,
            mmr,
            http_client,
        }
    }

    /// Registers a business partner in the local registry.
    pub fn register_business(&self, id: &str, name: &str, public_key: &str) {
        let profile = BusinessProfile {
            id: id.to_string(),
            name: name.to_string(),
            public_key: public_key.to_string(),
            active: true,
        };
        self.businesses.register_business(profile);
    }

    /// Registers a new asset in the local registry.
    pub fn register_asset(&self, chain: &str, symbol: &str, name: &str, decimals: u8, contract: Option<String>) {
        let chain_enum = match chain.to_uppercase().as_str() {
            "BITCOIN" => Chain::BITCOIN,
            "ETHEREUM" => Chain::ETHEREUM,
            "STACKS" => Chain::STACKS,
            "LIQUID" => Chain::LIQUID,
            "SOLANA" => Chain::SOLANA,
            "ARBITRUM" => Chain::ARBITRUM,
            "BASE" => Chain::BASE,
            "LIGHTNING" => Chain::LIGHTNING,
            _ => Chain::BITCOIN, // Default
        };

        let id = AssetIdentifier { chain: chain_enum, symbol: symbol.to_string() };
        let metadata = AssetMetadata { name: name.to_string(), decimals, contract_address: contract };
        self.assets.register_asset(id, metadata);
    }

    /// Generates a hardware-backed business identity.
    pub async fn generate_business_identity(&self, business_id: &str, name: &str) -> Result<JsValue, JsValue> {
        let mgr = BusinessManager::new(self.enclave.as_ref(), self.businesses.as_ref());
        let profile = mgr.generate_business_identity(business_id, name)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        serde_wasm_bindgen::to_value(&profile).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    /// Generates a signed proof of attribution for a business partner.
    pub async fn generate_attribution(&self, business_id: &str, user_id: &str, metadata: JsValue) -> Result<JsValue, JsValue> {
        let metadata_map: HashMap<String, String> = serde_wasm_bindgen::from_value(metadata)
            .map_err(|_| JsValue::from_str("Invalid metadata format"))?;

        let mgr = BusinessManager::new(self.enclave.as_ref(), self.businesses.as_ref());
        let attribution = mgr.generate_attribution(business_id, user_id, metadata_map)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        serde_wasm_bindgen::to_value(&attribution).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub async fn execute_swap(
        &self,
        provider: &str,
        intent: JsValue,
        attribution: Option<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let intent_json: serde_json::Value = serde_wasm_bindgen::from_value(intent)
            .map_err(|_| JsValue::from_str("Invalid intent JSON"))?;

        let attr: Option<BusinessAttribution> = if let Some(a) = attribution {
            Some(serde_wasm_bindgen::from_value(a).map_err(|_| JsValue::from_str("Invalid attribution format"))?)
        } else {
            None
        };

        let result = self.rails.execute_swap(provider, intent_json, attr).await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub async fn create_fiat_session(&self, intent_json: &str) -> Result<String, JsValue> {
        let intent = serde_json::from_str(intent_json)
            .map_err(|_| JsValue::from_str("Invalid fiat intent"))?;

        self.fiat.create_session(self.enclave.as_ref(), intent).await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub async fn verify_phone(&self, intent_json: &str) -> Result<String, JsValue> {
        let intent = serde_json::from_str(intent_json)
            .map_err(|_| JsValue::from_str("Invalid a2p intent"))?;

        self.a2p.verify_phone(self.enclave.as_ref(), intent).await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub async fn get_mmr_proof(&self, position: u64) -> Result<JsValue, JsValue> {
        let proof = self.mmr.get_proof(position).await
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        serde_wasm_bindgen::to_value(&proof).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub fn generate_job_card(&self, invoice: &str) -> Result<String, JsValue> {
        let mgr = CJCSManager::new();
        mgr.generate_card(invoice)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    pub fn derive_taproot_address(&self, path: &str) -> Result<String, JsValue> {
        let mgr = TaprootManager::new(self.enclave.as_ref());
        mgr.derive_address(path)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }
}
