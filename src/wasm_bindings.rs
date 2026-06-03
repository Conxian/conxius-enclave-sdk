use crate::ConclaveResult;
use crate::enclave::EnclaveManager;
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::a2p::{A2pRouterService, A2pSessionIntent};
use crate::protocol::asset::{AssetIdentifier, AssetMetadata, AssetRegistry, Chain};
use crate::protocol::bitcoin::{BitcoinManager, TaprootManager};
use crate::protocol::business::{BusinessManager, BusinessProfile, BusinessRegistry};
use crate::protocol::dlc::DlcManager;
use crate::protocol::economy::{DualStackIntent, YieldEngine};
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::fiat::{FiatRouterService, FiatSessionIntent};
use crate::protocol::mmr::MmrService;
use crate::protocol::opportunity::{OpportunityDispatcher, OpportunityPayload};
use crate::protocol::rails::{RailProxy, SovereignHandshake, SwapIntent};
use crate::protocol::sidl::{SidlCartMandate, SidlService, SidlVote};
use crate::protocol::solana::SolanaManager;
use crate::protocol::zkml::{ZkmlProofRequest, ZkmlService};
use crate::telemetry::TelemetryClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    pub gateway_url: String,
    pub enforce_attestation: bool,
}

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    config: SdkConfig,
    enclave: Arc<dyn EnclaveManager>,
    assets: Arc<AssetRegistry>,
    businesses: Arc<BusinessRegistry>,
    rails: Arc<RailProxy>,
    fiat: Arc<FiatRouterService>,
    a2p: Arc<A2pRouterService>,
    mmr: Arc<MmrService>,
    zkml: Arc<ZkmlService>,
    sidl: Arc<SidlService>,
    identity: Arc<crate::protocol::identity::IdentityManager>,
    dlc: Arc<DlcManager>,
    telemetry: Option<Arc<TelemetryClient>>,
    http_client: reqwest::Client,
}

fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(gateway_url: &str, use_cloud: bool) -> Result<ConclaveWasmClient, JsValue> {
        let config = SdkConfig {
            gateway_url: gateway_url.to_string(),
            enforce_attestation: true,
        };

        let enclave: Arc<dyn EnclaveManager> = if use_cloud {
            Arc::new(CloudEnclave::new(gateway_url.to_string()).map_err(to_js_error)?)
        } else {
            Arc::new(CoreEnclaveManager::new())
        };

        let assets = Arc::new(AssetRegistry::new());
        let businesses = Arc::new(BusinessRegistry::new());
        let http_client = reqwest::Client::new();
        let telemetry = None;

        let rails_obj = RailProxy::new(
            gateway_url.to_string(),
            http_client.clone(),
            assets.clone(),
            businesses.clone(),
        );

        let rails = Arc::new(rails_obj);
        let fiat = Arc::new(FiatRouterService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let a2p = Arc::new(A2pRouterService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let mmr = Arc::new(MmrService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let zkml = Arc::new(ZkmlService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let sidl = Arc::new(SidlService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let identity = Arc::new(crate::protocol::identity::IdentityManager::new(
            enclave.clone(),
        ));
        let dlc = Arc::new(DlcManager::with_enclave(enclave.clone()));

        Ok(Self {
            config,
            enclave,
            assets,
            businesses,
            rails,
            fiat,
            a2p,
            mmr,
            zkml,
            sidl,
            identity,
            dlc,
            telemetry,
            http_client,
        })
    }

    pub async fn unlock_enclave(&self, secret: &str, salt: &str) -> Result<(), JsValue> {
        let salt_bytes = hex::decode(salt).map_err(|_| JsValue::from_str("Invalid salt hex"))?;
        self.enclave
            .unlock(secret, &salt_bytes)
            .map_err(to_js_error)
    }

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
            "SOLANA" => Chain::SOLANA,
            "POLYGON" => Chain::POLYGON,
            "BSC" => Chain::BSC,
            _ => Chain::BITCOIN,
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

    pub fn ethereum(&self) -> EthereumManager<'_> {
        EthereumManager::new(self.enclave.as_ref())
    }

    pub fn solana(&self) -> SolanaManager<'_> {
        SolanaManager::new(self.enclave.as_ref())
    }

    pub fn bitcoin(&self) -> BitcoinManager {
        BitcoinManager::new(self.enclave.clone())
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

    pub async fn get_block_height(&self, chain: &str) -> Result<u64, JsValue> {
        match chain.to_uppercase().as_str() {
            "BITCOIN" => Ok(840000),
            "STACKS" => Ok(150000),
            _ => Err(JsValue::from_str("Unsupported chain for block height")),
        }
    }
}

#[wasm_bindgen]
pub struct Iso20022Wrapper;
#[wasm_bindgen]
impl Iso20022Wrapper {
    pub fn wrap_pacs008(
        _card: &crate::protocol::job_card::ConxianJobCard,
    ) -> ConclaveResult<String> {
        Ok("MOCK_ISO_XML".to_string())
    }
}
