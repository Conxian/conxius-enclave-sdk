use crate::enclave::EnclaveManager;
use crate::enclave::android_strongbox::CoreEnclaveManager;
use crate::enclave::cloud::CloudEnclave;
use crate::protocol::a2p::A2pRouterService;
use crate::protocol::ark::ArkManager;
use crate::protocol::asset::AssetRegistry;
use crate::protocol::bitcoin::BitcoinManager;
use crate::protocol::bitvm::BitVmManager;
use crate::protocol::business::BusinessRegistry;
use crate::protocol::chain_abstraction::ChainAbstractionService;
use crate::protocol::credit::CreditService;
use crate::protocol::dlc::DlcManager;
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::fiat::FiatRouterService;
use crate::protocol::intent::{SwapIntent, SwapRequest};
use crate::protocol::mmr::MmrService;
use crate::protocol::rails::{RailProxy, SovereignHandshake};
use crate::protocol::solana::SolanaManager;
use crate::protocol::zkml::ZkmlService;
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
    pub(crate) config: SdkConfig,
    pub(crate) enclave: Arc<dyn EnclaveManager>,
    pub(crate) rails: Arc<RailProxy>,
    pub(crate) fiat: Arc<FiatRouterService>,
    pub(crate) a2p: Arc<A2pRouterService>,
    pub(crate) mmr: Arc<MmrService>,
    pub(crate) credit: Arc<CreditService>,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: JsValue, enclave_type: &str) -> Result<ConclaveWasmClient, JsValue> {
        let config: SdkConfig = serde_wasm_bindgen::from_value(config_json)
            .map_err(|_| JsValue::from_str("Invalid config JSON"))?;

        let enclave: Arc<dyn EnclaveManager> = match enclave_type {
            "cloud" => {
                Arc::new(CloudEnclave::new(config.gateway_url.clone()).map_err(|e| e.to_string())?)
            }
            "android" => Arc::new(CoreEnclaveManager::new()),
            _ => return Err(JsValue::from_str("Unsupported enclave type")),
        };

        let asset_registry = Arc::new(AssetRegistry::new());
        let business_registry = Arc::new(BusinessRegistry::new());
        let client = reqwest::Client::new();

        let rails = Arc::new(RailProxy::new(
            config.gateway_url.clone(),
            client.clone(),
            asset_registry.clone(),
            business_registry,
        ));

        let fiat = Arc::new(FiatRouterService::new(
            config.gateway_url.clone(),
            client.clone(),
        ));
        let a2p = Arc::new(A2pRouterService::new(
            config.gateway_url.clone(),
            client.clone(),
        ));
        let mmr = Arc::new(MmrService::new(config.gateway_url.clone(), client.clone()));
        let credit = Arc::new(CreditService::new(
            config.gateway_url.clone(),
            client.clone(),
        ));

        Ok(ConclaveWasmClient {
            config,
            enclave,
            rails,
            fiat,
            a2p,
            mmr,
            credit,
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
            credit: self.credit.clone(),
        }
    }

    pub fn identity(&self) -> WasmIdentityClient {
        WasmIdentityClient {
            inner: Arc::new(crate::protocol::identity::IdentityManager::new(
                self.enclave.clone(),
            )),
        }
    }

    pub fn universal(&self) -> WasmUniversalClient {
        WasmUniversalClient {
            inner: Arc::new(ChainAbstractionService::new(
                self.enclave.clone(),
                self.rails.registry.clone(),
            )),
        }
    }

    pub fn dlc(&self) -> WasmDlcClient {
        WasmDlcClient {
            inner: Arc::new(crate::protocol::dlc::DlcManager::new()),
        }
    }

    pub fn zkml(&self) -> WasmZkmlClient {
        WasmZkmlClient {
            inner: Arc::new(ZkmlService::new(
                self.config.gateway_url.clone(),
                reqwest::Client::new(),
            )),
        }
    }

    pub fn ark(&self) -> WasmArkClient {
        WasmArkClient {
            inner: Arc::new(ArkManager::new(self.enclave.clone())),
        }
    }

    pub fn bitvm(&self) -> WasmBitVmClient {
        WasmBitVmClient {
            inner: Arc::new(BitVmManager::new(self.enclave.clone())),
        }
    }
}

#[wasm_bindgen]
pub struct WasmSigningClient {
    #[wasm_bindgen(skip)]
    pub enclave: Arc<dyn EnclaveManager>,
}

#[wasm_bindgen]
impl WasmSigningClient {
    pub fn get_public_key(&self, derivation_path: &str) -> Result<String, JsValue> {
        self.enclave
            .get_public_key(derivation_path)
            .map_err(to_js_error)
    }

    pub fn sign(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let req = serde_wasm_bindgen::from_value(request).map_err(to_js_error)?;
        let response = self.enclave.sign(req).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&response).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmSwapClient {
    #[wasm_bindgen(skip)]
    pub rails: Arc<RailProxy>,
    #[wasm_bindgen(skip)]
    pub fiat: Arc<FiatRouterService>,
    #[wasm_bindgen(skip)]
    pub credit: Arc<CreditService>,
}

#[wasm_bindgen]
impl WasmSwapClient {
    pub fn prepare_intent(&self, rail_name: &str, request: JsValue) -> Result<JsValue, JsValue> {
        let req: SwapRequest = serde_wasm_bindgen::from_value(request)
            .map_err(|_| JsValue::from_str("Invalid request format"))?;
        let intent = self
            .rails
            .prepare_intent(rail_name, req, None)
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&intent).map_err(to_js_error)
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
        let req: crate::protocol::fiat::FiatOnRampRequest =
            serde_wasm_bindgen::from_value(request).map_err(|_| JsValue::from_str("Invalid request format"))?;
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
    pub fn offer_contract(
        &self,
        oracle: &str,
        local: u64,
        remote: u64,
    ) -> Result<JsValue, JsValue> {
        let contract = self
            .inner
            .offer_contract(oracle, local, remote)
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&contract).map_err(to_js_error)
    }

    pub fn accept_contract(
        &self,
        contract: JsValue,
        remote_pubkey: &str,
    ) -> Result<JsValue, JsValue> {
        let contract_obj = serde_wasm_bindgen::from_value(contract).map_err(to_js_error)?;
        let accepted = self
            .inner
            .accept_contract(contract_obj, remote_pubkey.to_string())
            .map_err(to_js_error)?;
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
        let proof = self
            .inner
            .generate_compliance_proof(req)
            .await
            .map_err(to_js_error)?;
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
    pub fn sign_challenge(
        &self,
        challenge: JsValue,
        path: &str,
        key_id: &str,
    ) -> Result<String, JsValue> {
        let chal = serde_wasm_bindgen::from_value(challenge).map_err(to_js_error)?;
        self.inner
            .sign_challenge(chal, path, key_id)
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

#[wasm_bindgen]
impl WasmEthereumManager {
    pub fn prepare_erc20_transfer(
        &self,
        to: &str,
        amount: &str,
        contract: &str,
    ) -> Result<Vec<u8>, JsValue> {
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
    pub fn prepare_spl_transfer(
        &self,
        source: &str,
        dest: &str,
        amount: u64,
        owner: &str,
    ) -> Result<Vec<u8>, JsValue> {
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

    pub fn settlement_context(
        amount: &str,
        asset: &str,
        recipient: &str,
    ) -> Result<JsValue, JsValue> {
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

#[wasm_bindgen]
pub struct WasmFrostClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::frost::FrostManager,
}

#[wasm_bindgen]
impl WasmFrostClient {
    pub fn generate_key_package(
        &self,
        min_signers: u32,
        total_signers: u32,
        identifier: &str,
    ) -> Result<JsValue, JsValue> {
        let package = crate::protocol::frost::FrostManager::generate_key_package(
            min_signers,
            total_signers,
            identifier,
        )
        .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&package).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmCovenantClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::covenant::CovenantManager,
}

#[wasm_bindgen]
impl WasmCovenantClient {
    pub fn generate_cat_vault_script(
        &self,
        internal_key_hex: &str,
        template_hash_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let pk_bytes = hex::decode(internal_key_hex).map_err(to_js_error)?;
        let pk_arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid key length"))?;
        let pk = bitcoin::XOnlyPublicKey::from_byte_array(&pk_arr).map_err(to_js_error)?;
        let hash_bytes = hex::decode(template_hash_hex).map_err(to_js_error)?;
        let hash: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid hash length"))?;

        let script =
            crate::protocol::covenant::CovenantManager::generate_cat_vault_script(&pk, hash)
                .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&script).map_err(to_js_error)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn frost(&self) -> WasmFrostClient {
        WasmFrostClient {
            inner: crate::protocol::frost::FrostManager,
        }
    }

    pub fn covenants(&self) -> WasmCovenantClient {
        WasmCovenantClient {
            inner: crate::protocol::covenant::CovenantManager,
        }
    }
}

fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}
