use crate::enclave::EnclaveManager;
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::a2p::A2pRouterService;
use crate::protocol::asset::{AssetIdentifier, AssetMetadata, AssetRegistry, Chain};
use crate::protocol::bitcoin::BitcoinManager;
use crate::protocol::business::BusinessRegistry;
use crate::protocol::credit::CreditService;
use crate::protocol::dlc::{DlcManager, DlcState};
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::fiat::{FiatOnRampRequest, FiatRouterService};
use crate::protocol::mmr::MmrService;
use crate::protocol::rails::{RailProxy, SovereignHandshake, SwapIntent};
use crate::protocol::sidl::SidlService;
use crate::protocol::solana::SolanaManager;
use crate::protocol::zkml::ZkmlService;
use crate::protocol::chain_abstraction::ChainAbstractionService;
use crate::protocol::ark::ArkManager;
use crate::protocol::bitvm::BitVmManager;
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
    #[allow(dead_code)]
    config: SdkConfig,
    enclave: Arc<dyn EnclaveManager>,
    assets: Arc<AssetRegistry>,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    identity: Arc<crate::protocol::identity::IdentityManager>,
    #[allow(dead_code)]
    dlc: Arc<DlcManager>,
    #[allow(dead_code)]
    universal: Arc<ChainAbstractionService>,
    #[allow(dead_code)]
    ark: Arc<ArkManager>,
    #[allow(dead_code)]
    bitvm: Arc<BitVmManager>,
    #[allow(dead_code)]
    telemetry: Option<Arc<TelemetryClient>>,
    #[allow(dead_code)]
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
        let universal = Arc::new(ChainAbstractionService::new(enclave.clone(), assets.clone()));
        let ark = Arc::new(ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(BitVmManager::new(enclave.clone()));

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
            ark,
            bitvm,
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

    pub fn identity(&self) -> WasmIdentityClient {
        WasmIdentityClient {
            inner: self.identity.clone(),
        }
    }

    pub fn universal(&self) -> WasmUniversalClient {
        WasmUniversalClient {
            inner: self.universal.clone(),
        }
    }

    pub fn dlc(&self) -> WasmDlcClient {
        WasmDlcClient {
            inner: self.dlc.clone(),
        }
    }

    pub fn zkml(&self) -> WasmZkmlClient {
        WasmZkmlClient {
            inner: self.zkml.clone(),
        }
    }

    pub fn ark(&self) -> WasmArkClient {
        WasmArkClient {
            inner: self.ark.clone(),
        }
    }

    pub fn bitvm(&self) -> WasmBitVmClient {
        WasmBitVmClient {
            inner: self.bitvm.clone(),
        }
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

    pub async fn prepare_fiat_session(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let req: FiatOnRampRequest = serde_wasm_bindgen::from_value(request)
            .map_err(|_| JsValue::from_str("Invalid request format"))?;
        let intent = self.fiat.prepare_session(req);
        serde_wasm_bindgen::to_value(&intent).map_err(to_js_error)
    }

    pub async fn prepare_vouch(
        &self,
        borrower: String,
        vouchers: Vec<String>,
        amount: u64,
    ) -> Result<JsValue, JsValue> {
        let intent = self.credit.prepare_vouch(borrower, vouchers, amount);
        serde_wasm_bindgen::to_value(&intent).map_err(to_js_error)
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
pub struct WasmIdentityClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<crate::protocol::identity::IdentityManager>,
}

#[wasm_bindgen]
impl WasmIdentityClient {
    pub fn create_identity(&self) -> Result<JsValue, JsValue> {
        let profile = self.inner.create_identity().map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&profile).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmUniversalClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ChainAbstractionService>,
}

#[wasm_bindgen]
impl WasmUniversalClient {
    pub fn resolve_intent(&self, intent: JsValue) -> Result<JsValue, JsValue> {
        let intent_obj = serde_wasm_bindgen::from_value(intent).map_err(to_js_error)?;
        let resolved = self.inner.resolve_intent(intent_obj).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&resolved).map_err(to_js_error)
    }

    pub fn sign_for_chain(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let req = serde_wasm_bindgen::from_value(request).map_err(to_js_error)?;
        let response = self.inner.sign_for_chain(req).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&response).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmDlcClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<DlcManager>,
}

#[wasm_bindgen]
impl WasmDlcClient {
    pub fn offer_contract(&self, oracle: &str, local: u64, remote: u64) -> Result<JsValue, JsValue> {
        let contract = self.inner.offer_contract(oracle, local, remote).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&contract).map_err(to_js_error)
    }

    pub fn accept_contract(&self, contract: JsValue, remote_pubkey: &str) -> Result<JsValue, JsValue> {
        let contract_obj = serde_wasm_bindgen::from_value(contract).map_err(to_js_error)?;
        let accepted = self.inner.accept_contract(contract_obj, remote_pubkey.to_string()).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&accepted).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmZkmlClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ZkmlService>,
}

#[wasm_bindgen]
impl WasmZkmlClient {
    pub async fn generate_compliance_proof(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let req = serde_wasm_bindgen::from_value(request).map_err(to_js_error)?;
        let proof = self.inner.generate_compliance_proof(req).await.map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&proof).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmArkClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ArkManager>,
}

#[wasm_bindgen]
impl WasmArkClient {
    pub fn derive_vutxo_key(&self, seed_hex: &str, index: u32) -> Result<String, JsValue> {
        let seed = hex::decode(seed_hex).map_err(to_js_error)?;
        let key = self.inner.derive_vutxo_key(&seed, index);
        Ok(hex::encode(key))
    }
}

#[wasm_bindgen]
pub struct WasmBitVmClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<BitVmManager>,
}

#[wasm_bindgen]
impl WasmBitVmClient {
    pub fn sign_challenge(&self, challenge: JsValue, path: &str, key_id: &str) -> Result<String, JsValue> {
        let chal = serde_wasm_bindgen::from_value(challenge).map_err(to_js_error)?;
        self.inner.sign_challenge(chal, path, key_id).map_err(to_js_error)
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

#[wasm_bindgen]
impl WasmEthereumManager {
    pub fn prepare_erc20_transfer(&self, to: &str, amount: &str, contract: &str) -> Result<Vec<u8>, JsValue> {
        let amt = amount.parse::<u128>().map_err(to_js_error)?;
        let transfer = crate::protocol::ethereum::Erc20Transfer {
            to: to.to_string(),
            amount: amt,
            contract_address: contract.to_string(),
        };
        Ok(EthereumManager::new(self.enclave.as_ref()).prepare_erc20_transfer(transfer))
    }
}

#[wasm_bindgen]
impl WasmSolanaManager {
    pub fn prepare_spl_transfer(&self, source: &str, dest: &str, amount: u64, owner: &str) -> Result<Vec<u8>, JsValue> {
        let transfer = crate::protocol::solana::SplTransfer {
            source_token_account: source.to_string(),
            destination_token_account: dest.to_string(),
            amount,
            owner: owner.to_string(),
        };
        Ok(SolanaManager::new(self.enclave.as_ref()).prepare_spl_transfer(transfer))
    }
}

#[wasm_bindgen]
pub struct WasmAccountClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::account_abstraction::ModularAccountManager,
}

#[wasm_bindgen]
impl WasmAccountClient {
    pub fn prepare_execution(&self, actions: JsValue) -> Result<JsValue, JsValue> {
        let acts = serde_wasm_bindgen::from_value(actions).map_err(to_js_error)?;
        let execution = self.inner.prepare_execution(acts);
        serde_wasm_bindgen::to_value(&execution).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmCctpClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::cctp::CctpManager,
}

#[wasm_bindgen]
impl WasmCctpClient {
    pub fn prepare_burn_payload(&self, intent: JsValue) -> Result<Vec<u8>, JsValue> {
        let intent_obj = serde_wasm_bindgen::from_value(intent).map_err(to_js_error)?;
        Ok(self.inner.prepare_burn_payload(intent_obj))
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn accounts(&self) -> WasmAccountClient {
        WasmAccountClient {
            inner: crate::protocol::account_abstraction::ModularAccountManager::new(),
        }
    }

    pub fn cctp(&self) -> WasmCctpClient {
        WasmCctpClient {
            inner: crate::protocol::cctp::CctpManager::new(),
        }
    }
}

#[wasm_bindgen]
pub struct WasmIntentClient;

#[wasm_bindgen]
impl WasmIntentClient {
    pub fn instrument_context(symbol: &str, chain: &str) -> Result<JsValue, JsValue> {
        let ctx = crate::protocol::intent::Fdc3Context::instrument(symbol, chain);
        serde_wasm_bindgen::to_value(&ctx).map_err(to_js_error)
    }

    pub fn settlement_context(amount: &str, asset: &str, recipient: &str) -> Result<JsValue, JsValue> {
        let amt = amount.parse::<u128>().map_err(to_js_error)?;
        let ctx = crate::protocol::intent::Fdc3Context::settlement(amt, asset, recipient);
        serde_wasm_bindgen::to_value(&ctx).map_err(to_js_error)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn intent(&self) -> WasmIntentClient {
        WasmIntentClient
    }
}
