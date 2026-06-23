use crate::enclave::EnclaveManager;
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::a2p::A2pRouterService;
use crate::protocol::asset::{AssetIdentifier, AssetMetadata, AssetRegistry, Chain};
use crate::protocol::bitcoin::BitcoinManager;
use crate::protocol::business::BusinessRegistry;
use crate::protocol::chain_abstraction::ChainAbstractionService;
use crate::protocol::credit::CreditService;
use crate::protocol::dlc::DlcManager;
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::fiat::{FiatOnRampRequest, FiatRouterService};
use crate::protocol::mmr::MmrService;
use crate::protocol::rails::{RailProxy, SovereignHandshake, SwapIntent};
use crate::protocol::sidl::SidlService;
use crate::protocol::solana::SolanaManager;
use crate::protocol::zkml::ZkmlService;
use crate::telemetry::TelemetryClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    #[wasm_bindgen(getter_with_clone)]
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
    credit: Arc<CreditService>,
    #[allow(dead_code)]
    a2p: Arc<A2pRouterService>,
    #[allow(dead_code)]
    mmr: Arc<MmrService>,
    #[allow(dead_code)]
    zkml: Arc<ZkmlService>,
    #[allow(dead_code)]
    sidl: Arc<SidlService>,
    identity: Arc<crate::protocol::identity::IdentityManager>,
    #[allow(dead_code)]
    dlc: Arc<DlcManager>,
    universal: Arc<ChainAbstractionService>,
    #[allow(dead_code)]
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

        let rails = Arc::new(RailProxy::new(
            gateway_url.to_string(),
            http_client.clone(),
            assets.clone(),
            businesses.clone(),
        ));

        let fiat = Arc::new(FiatRouterService::new(
            gateway_url.to_string(),
            http_client.clone(),
        ));
        let credit = Arc::new(CreditService::new(
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
        let universal = Arc::new(ChainAbstractionService::new(enclave.clone()));

        Ok(Self {
            config,
            enclave,
            assets,
            businesses,
            rails,
            fiat,
            credit,
            a2p,
            mmr,
            zkml,
            sidl,
            identity,
            dlc,
            universal,
            telemetry,
            http_client,
        })
    }

    pub fn signing(&self) -> WasmSigningClient {
        WasmSigningClient {
            enclave: self.enclave.clone(),
        }
    }

    pub fn swaps(&self) -> WasmSwapClient {
        WasmSwapClient {
            rails: self.rails.clone(),
            fiat: self.fiat.clone(),
        }
    }

    pub fn identity(&self) -> WasmIdentityClient {
        WasmIdentityClient {
            identity: self.identity.clone(),
            businesses: self.businesses.clone(),
        }
    }

    pub fn credit(&self) -> WasmCreditClient {
        WasmCreditClient {
            credit: self.credit.clone(),
        }
    }

    pub fn bitcoin_l2(&self) -> WasmBitcoinL2Client {
        WasmBitcoinL2Client {
            ark: Arc::new(crate::protocol::ark::ArkManager::new(self.enclave.clone())),
            bitvm: Arc::new(crate::protocol::bitvm::BitVmManager::new(
                self.enclave.clone(),
            )),
        }
    }

    pub fn universal(&self) -> WasmUniversalClient {
        WasmUniversalClient {
            inner: self.universal.clone(),
        }
    }

    /// Convenience method for unlocking the enclave.
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
            "ROOTSTOCK" => Chain::ROOTSTOCK,
            "BOB" => Chain::BOB,
            "MEZO" => Chain::MEZO,
            "BABYLON" => Chain::BABYLON,
            "BOTANIX" => Chain::BOTANIX,
            "CITREA" => Chain::CITREA,
            "COSMOS" => Chain::COSMOS,
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

    pub fn ethereum(&self) -> WasmEthereumManager {
        WasmEthereumManager {
            enclave: self.enclave.clone(),
        }
    }

    pub fn solana(&self) -> WasmSolanaManager {
        WasmSolanaManager {
            enclave: self.enclave.clone(),
        }
    }

    pub fn bitcoin(&self) -> WasmBitcoinManager {
        WasmBitcoinManager {
            inner: BitcoinManager::new(self.enclave.clone()),
        }
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
pub struct WasmSigningClient {
    enclave: Arc<dyn EnclaveManager>,
}

#[wasm_bindgen]
impl WasmSigningClient {
    pub async fn unlock(&self, secret: &str, salt: &str) -> Result<(), JsValue> {
        let salt_bytes = hex::decode(salt).map_err(|_| JsValue::from_str("Invalid salt hex"))?;
        self.enclave
            .unlock(secret, &salt_bytes)
            .map_err(to_js_error)
    }

    pub fn get_public_key(&self, derivation_path: &str) -> Result<String, JsValue> {
        self.enclave
            .get_public_key(derivation_path)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmSwapClient {
    rails: Arc<RailProxy>,
    fiat: Arc<FiatRouterService>,
}

#[wasm_bindgen]
impl WasmSwapClient {
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

    pub async fn prepare_fiat_session(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let req: FiatOnRampRequest = serde_wasm_bindgen::from_value(request)
            .map_err(|_| JsValue::from_str("Invalid request format"))?;
        let intent = self.fiat.prepare_session(req);
        serde_wasm_bindgen::to_value(&intent).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmIdentityClient {
    identity: Arc<crate::protocol::identity::IdentityManager>,
    #[allow(dead_code)]
    businesses: Arc<BusinessRegistry>,
}

#[wasm_bindgen]
impl WasmIdentityClient {
    pub fn create_identity(&self) -> Result<JsValue, JsValue> {
        let profile = self.identity.create_identity().map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&profile).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmCreditClient {
    credit: Arc<CreditService>,
}

#[wasm_bindgen]
impl WasmCreditClient {
    pub async fn prepare_vouch(
        &self,
        borrower: String,
        vouchers: Vec<String>,
        amount: u64,
    ) -> Result<JsValue, JsValue> {
        let intent = self.credit.prepare_vouch(borrower, vouchers, amount);
        serde_wasm_bindgen::to_value(&intent).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmBitcoinL2Client {
    ark: Arc<crate::protocol::ark::ArkManager>,
    bitvm: Arc<crate::protocol::bitvm::BitVmManager>,
}

#[wasm_bindgen]
impl WasmBitcoinL2Client {
    pub fn derive_vutxo_key(&self, master_seed: Vec<u8>, index: u32) -> String {
        let key = self.ark.derive_vutxo_key(&master_seed, index);
        hex::encode(key)
    }

    pub fn sign_bitvm_challenge(
        &self,
        challenge_hash_hex: &str,
        derivation_path: &str,
        key_id: &str,
    ) -> Result<String, JsValue> {
        let challenge_hash_bytes = hex::decode(challenge_hash_hex).map_err(to_js_error)?;
        let mut challenge_hash = [0u8; 32];
        challenge_hash.copy_from_slice(&challenge_hash_bytes);

        let challenge = crate::protocol::bitvm::BitVmChallenge {
            challenge_hash,
            tap_index: 0,
            total_taps: 364,
        };

        self.bitvm
            .sign_challenge(challenge, derivation_path, key_id)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmUniversalClient {
    inner: Arc<ChainAbstractionService>,
}

#[wasm_bindgen]
impl WasmUniversalClient {
    pub async fn sign_chain_transaction(
        &self,
        chain: &str,
        payload_hex: &str,
        derivation_path: &str,
    ) -> Result<JsValue, JsValue> {
        let chain_enum = match chain.to_uppercase().as_str() {
            "BITCOIN" => Chain::BITCOIN,
            "ETHEREUM" => Chain::ETHEREUM,
            "SOLANA" => Chain::SOLANA,
            "NEAR" => Chain::NEAR,
            "COSMOS" => Chain::COSMOS,
            _ => Chain::BITCOIN,
        };

        let payload = hex::decode(payload_hex).map_err(to_js_error)?;

        let req = crate::protocol::chain_abstraction::ChainSignatureRequest {
            target_chain: chain_enum,
            transaction_payload: payload,
            derivation_path: derivation_path.to_string(),
        };

        let resp = self
            .inner
            .sign_chain_transaction(req)
            .await
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&resp).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmBitcoinManager {
    #[wasm_bindgen(skip)]
    pub inner: BitcoinManager,
}

#[wasm_bindgen]
impl WasmBitcoinManager {
    pub fn generate_wpkh_descriptor(&self, derivation_path: &str) -> Result<String, JsValue> {
        self.inner
            .generate_wpkh_descriptor(derivation_path)
            .map_err(to_js_error)
    }

    pub fn generate_tr_descriptor(&self, derivation_path: &str) -> Result<String, JsValue> {
        self.inner
            .generate_tr_descriptor(derivation_path)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmEthereumManager {
    #[wasm_bindgen(skip)]
    pub enclave: Arc<dyn EnclaveManager>,
}

#[wasm_bindgen]
impl WasmEthereumManager {
    pub fn get_address(&self, derivation_path: &str) -> Result<String, JsValue> {
        EthereumManager::new(self.enclave.as_ref())
            .get_address(derivation_path)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmSolanaManager {
    #[wasm_bindgen(skip)]
    pub enclave: Arc<dyn EnclaveManager>,
}

#[wasm_bindgen]
impl WasmSolanaManager {
    pub fn get_address(&self, derivation_path: &str) -> Result<String, JsValue> {
        SolanaManager::new(self.enclave.as_ref())
            .get_address(derivation_path)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct Iso20022Wrapper;

#[wasm_bindgen]
impl Iso20022Wrapper {
    pub fn wrap_pacs008(card: JsValue) -> Result<String, JsValue> {
        let card: crate::protocol::job_card::ConxianJobCard =
            serde_wasm_bindgen::from_value(card).map_err(to_js_error)?;
        crate::protocol::job_card::Iso20022Wrapper::wrap_pacs008(&card).map_err(to_js_error)
    }
}
