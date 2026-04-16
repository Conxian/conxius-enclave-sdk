use crate::enclave::EnclaveManager;
#[cfg(target_arch = "wasm32")]
use crate::enclave::android_strongbox::CoreEnclaveManager as AndroidStrongBox;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::a2p::{A2pRouterService, A2pSessionIntent};
use crate::protocol::asset::{AssetIdentifier, AssetMetadata, AssetRegistry, Chain};
use crate::protocol::bitcoin::TaprootManager;
use crate::protocol::business::{BusinessManager, BusinessProfile, BusinessRegistry};
use crate::protocol::fiat::{FiatRouterService, FiatSessionIntent};
use crate::protocol::job_card::Iso20022Wrapper;
use crate::protocol::mmr::MmrService;
use crate::protocol::rails::{RailProxy, SovereignHandshake, SwapIntent};
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

fn to_js_error<E: Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    enclave: Arc<dyn EnclaveManager>,
    assets: Arc<AssetRegistry>,
    businesses: Arc<BusinessRegistry>,
    rails: Arc<RailProxy>,
    fiat: Arc<FiatRouterService>,
    a2p: Arc<A2pRouterService>,
    mmr: Arc<MmrService>,
    #[allow(dead_code)]
    http_client: reqwest::Client,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(gateway_url: &str, kms_endpoint: Option<String>) -> Result<Self, JsValue> {
        let http_client = reqwest::Client::new();
        let assets = Arc::new(AssetRegistry::new());
        let businesses = Arc::new(BusinessRegistry::new());

        #[cfg(target_arch = "wasm32")]
        let enclave: Arc<dyn EnclaveManager> = if let Some(kms) = kms_endpoint {
            Arc::new(CloudEnclave::new(kms).map_err(to_js_error)?)
        } else {
            Arc::new(AndroidStrongBox::new())
        };

        #[cfg(not(target_arch = "wasm32"))]
        let enclave: Arc<dyn EnclaveManager> = Arc::new(
            CloudEnclave::new(
                kms_endpoint.unwrap_or_else(|| "https://vault.conxian.io".to_string()),
            )
            .map_err(to_js_error)?,
        );

        let rails = Arc::new(RailProxy::new(
            gateway_url.to_string(),
            http_client.clone(),
            assets.clone(),
            businesses.clone(),
        ));

        let fiat = Arc::new(FiatRouterService::new(gateway_url.to_string()));
        let a2p = Arc::new(A2pRouterService::new(gateway_url.to_string()));
        let mmr = Arc::new(MmrService::new(gateway_url.to_string()));

        Ok(Self {
            enclave,
            assets,
            businesses,
            rails,
            fiat,
            a2p,
            mmr,
            http_client,
        })
    }

    /// Unlocks the secure enclave using a secret (PIN/Passphrase) and salt.
    pub async fn unlock_enclave(&self, secret: &str, salt: &str) -> Result<(), JsValue> {
        let salt_bytes = hex::decode(salt).map_err(|_| JsValue::from_str("Invalid salt hex"))?;
        self.enclave
            .unlock(secret, &salt_bytes)
            .map_err(to_js_error)
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
    pub fn register_asset(
        &self,
        chain: &str,
        symbol: &str,
        name: &str,
        decimals: u8,
        contract: Option<String>,
    ) {
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

        let id = AssetIdentifier {
            chain: chain_enum,
            symbol: symbol.to_string(),
        };
        let metadata = AssetMetadata {
            name: name.to_string(),
            decimals,
            contract_address: contract,
            active: true,
        };
        self.assets.register_asset(id, metadata);
    }

    /// Generates a hardware-backed business identity.
    pub async fn generate_business_identity(
        &self,
        business_id: &str,
        name: &str,
    ) -> Result<JsValue, JsValue> {
        let mgr = BusinessManager::new(self.enclave.as_ref(), self.businesses.as_ref());
        let profile = mgr
            .generate_business_identity(business_id, name)
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&profile).map_err(to_js_error)
    }

    /// Generates a signed proof of attribution for a business partner.
    pub async fn generate_attribution(
        &self,
        business_id: &str,
        user_id: &str,
        metadata: JsValue,
    ) -> Result<JsValue, JsValue> {
        let metadata_map: HashMap<String, String> = serde_wasm_bindgen::from_value(metadata)
            .map_err(|_| JsValue::from_str("Invalid metadata format"))?;

        let mgr = BusinessManager::new(self.enclave.as_ref(), self.businesses.as_ref());
        let attribution = mgr
            .generate_attribution(business_id, user_id, metadata_map)
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&attribution).map_err(to_js_error)
    }

    pub async fn execute_swap(
        &self,
        intent: JsValue,
        signature: String,
        attestation: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let intent_obj: SwapIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|_| JsValue::from_str("Invalid intent format"))?;

        let result = self
            .rails
            .broadcast_signed_intent(intent_obj, signature, attestation)
            .await
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&result).map_err(to_js_error)
    }

    pub async fn create_fiat_session(
        &self,
        intent: JsValue,
        signature: String,
    ) -> Result<JsValue, JsValue> {
        let intent_obj: FiatSessionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|_| JsValue::from_str("Invalid fiat intent format"))?;

        let result = self
            .fiat
            .create_session(intent_obj, signature)
            .await
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&result).map_err(to_js_error)
    }

    pub async fn initiate_a2p_verification(
        &self,
        intent: JsValue,
        signature: String,
    ) -> Result<JsValue, JsValue> {
        let intent_obj: A2pSessionIntent = serde_wasm_bindgen::from_value(intent)
            .map_err(|_| JsValue::from_str("Invalid a2p intent format"))?;

        let result = self
            .a2p
            .initiate_verification(intent_obj, signature)
            .await
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&result).map_err(to_js_error)
    }

    pub async fn get_mmr_proof(&self, node_id: &str) -> Result<JsValue, JsValue> {
        let proof = self
            .mmr
            .fetch_remote_proof(node_id)
            .await
            .map_err(to_js_error)?;

        serde_wasm_bindgen::to_value(&proof).map_err(to_js_error)
    }

    pub fn generate_job_card(
        &self,
        sender: &str,
        receiver: &str,
        amount_sbtc: String,
        town: Option<String>,
        country: Option<String>,
    ) -> Result<String, JsValue> {
        use crate::protocol::job_card::ConxianJobCard;
        let card = ConxianJobCard::new(sender, receiver, amount_sbtc, town, country);
        Iso20022Wrapper::wrap_pacs008(&card).map_err(to_js_error)
    }

    pub fn derive_taproot_address(&self, path: &str) -> Result<String, JsValue> {
        let mgr = TaprootManager::new(self.enclave.as_ref());
        mgr.derive_address(path).map_err(to_js_error)
    }
}
