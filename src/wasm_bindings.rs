use crate::enclave::EnclaveManager;
use crate::protocol::ark::ArkManager;
use crate::protocol::bitvm::BitVmManager;
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::solana::SolanaManager;
use crate::wasm_support::{self, WasmRuntime};
use crate::ConclaveError;
use bech32::{primitives::decode::CheckedHrpstring, Bech32};
use hex;
use serde_wasm_bindgen;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ConclaveWasmClient {
    enclave: Arc<dyn EnclaveManager>,
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(_enclave_url: &str) -> Result<ConclaveWasmClient, JsValue> {
        Err(unsupported_provider(
            "no verified opaque-key provider adapter is registered",
        ))
    }

    #[cfg(feature = "development-simulators")]
    pub fn new_for_development(enclave_url: &str) -> Result<ConclaveWasmClient, JsValue> {
        let enclave = Arc::new(
            crate::enclave::cloud::CloudEnclave::new_for_development(enclave_url.to_string())
                .map_err(to_js_error)?,
        );
        Ok(ConclaveWasmClient { enclave })
    }

    /// Check the support decision for a documented runtime before loading an
    /// artifact. All current runtimes fail closed until exact runtime and
    /// provider evidence is attached.
    pub fn check_runtime_support(runtime: &str) -> Result<(), JsValue> {
        let runtime = WasmRuntime::parse(runtime).map_err(conclave_error_to_js)?;
        wasm_support::reject_unverified_runtime(runtime).map_err(conclave_error_to_js)
    }

    /// Compatibility entry point for the future provider-backed constructor.
    /// It deliberately does not retain or inspect a JavaScript key object.
    pub fn new_with_provider(
        runtime: &str,
        _provider: JsValue,
    ) -> Result<ConclaveWasmClient, JsValue> {
        let _runtime = WasmRuntime::parse(runtime).map_err(conclave_error_to_js)?;
        wasm_support::reject_unapproved_provider("external-provider")
            .map_err(conclave_error_to_js)?;
        Err(unsupported_provider(
            "no verified opaque-key provider adapter is registered",
        ))
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
pub struct WasmArkClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<ArkManager>,
}

#[wasm_bindgen]
impl WasmArkClient {
    /// Retrieve a provider-owned public key without accepting or returning a
    /// seed/private key.
    pub fn derive_vutxo_public_key(&self, index: u32) -> Result<String, JsValue> {
        self.inner
            .derive_vutxo_public_key(index)
            .map_err(conclave_error_to_js)
    }

    /// Quarantined Ark signing entry point. No provider call is made.
    pub fn sign_vutxo(&self, tx_hash_hex: &str, index: u32) -> Result<String, JsValue> {
        let tx_hash: [u8; 32] = hex::decode(tx_hash_hex)
            .map_err(invalid_input)?
            .try_into()
            .map_err(|_| wasm_error("INVALID_INPUT", "transaction hash must be 32 bytes"))?;

        self.inner
            .sign_vutxo(tx_hash, index)
            .map_err(conclave_error_to_js)
    }

    pub async fn recovery_scan(&self, gap_limit: u32, asp_url: &str) -> Result<JsValue, JsValue> {
        let _ = (gap_limit, asp_url);
        Err(conclave_error_to_js(crate::protocol_unsupported(
            crate::UnsupportedProtocol::Ark,
            crate::UnsupportedOperation::RecoveryScan,
        )))
    }

    pub fn construct_vtxo_tree(&self, leaves: JsValue) -> Result<JsValue, JsValue> {
        let leaves_vec = serde_wasm_bindgen::from_value(leaves).map_err(invalid_input)?;
        let root = self
            .inner
            .construct_vtxo_tree(leaves_vec)
            .map_err(conclave_error_to_js)?;
        serde_wasm_bindgen::to_value(&root).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmBitVmClient {
    #[wasm_bindgen(skip)]
    pub inner: Arc<BitVmManager>,
}

#[wasm_bindgen]
impl WasmBitVmClient {
    /// Legacy BitVM signing is not BitVM2 challenge evidence. Keep this
    /// compatibility surface present, but fail before decoding inputs or
    /// invoking the native MuSig2 implementation.
    pub fn sign_challenge(
        &self,
        challenge: JsValue,
        path: &str,
        key_id: &str,
    ) -> Result<String, JsValue> {
        let _ = (&self.inner, challenge, path, key_id);
        Err(legacy_bitvm2_error(
            crate::UnsupportedOperation::ChallengeSubmission,
        ))
    }

    /// Legacy MuSig2 aggregation is not BitVM2 challenge evidence. No
    /// signature or aggregate is decoded or returned through this boundary.
    pub fn aggregate_challenge_signatures(
        &self,
        pubkeys_hex: JsValue,
        pub_nonces_hex: JsValue,
        partial_sigs_hex: JsValue,
        challenge: JsValue,
    ) -> Result<JsValue, JsValue> {
        let _ = (
            &self.inner,
            pubkeys_hex,
            pub_nonces_hex,
            partial_sigs_hex,
            challenge,
        );
        Err(legacy_bitvm2_error(
            crate::UnsupportedOperation::ThresholdAggregation,
        ))
    }
}

#[wasm_bindgen]
pub struct Iso20022Wrapper;

#[wasm_bindgen]
impl Iso20022Wrapper {
    pub fn wrap_pacs008(card: JsValue) -> Result<String, JsValue> {
        let card: crate::protocol::job_card::ConxianJobCard =
            serde_wasm_bindgen::from_value(card).map_err(invalid_input)?;
        crate::protocol::job_card::Iso20022Wrapper::wrap_pacs008(&card).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmEthereumManager {
    #[wasm_bindgen(skip)]
    pub enclave: Arc<dyn EnclaveManager>,
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
        EthereumManager::new(self.enclave.as_ref())
            .prepare_erc20_transfer(transfer)
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
        let acts = serde_wasm_bindgen::from_value(actions).map_err(invalid_input)?;
        let execution = self.inner.prepare_execution(acts).map_err(to_js_error)?;
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
        let intent_obj = serde_wasm_bindgen::from_value(intent).map_err(invalid_input)?;
        self.inner
            .prepare_burn_payload(intent_obj)
            .map_err(to_js_error)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
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
        let amt = amount.parse::<u128>().map_err(invalid_input)?;
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
        .map_err(conclave_error_to_js)?;
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
        let pk_bytes = hex::decode(internal_key_hex).map_err(invalid_input)?;
        let pk_arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| wasm_error("INVALID_INPUT", "key must be 32 bytes"))?;
        let pk = bitcoin::XOnlyPublicKey::from_byte_array(&pk_arr).map_err(invalid_input)?;
        let hash_bytes = hex::decode(template_hash_hex).map_err(invalid_input)?;
        let hash: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| wasm_error("INVALID_INPUT", "hash must be 32 bytes"))?;

        let script =
            crate::protocol::covenant::CovenantManager::generate_cat_vault_script(&pk, hash)
                .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&script).map_err(to_js_error)
    }

    pub fn verify_recursive_invariant(
        &self,
        witness: JsValue,
        expected_hash_hex: &str,
    ) -> Result<bool, JsValue> {
        let witness_vec: Vec<Vec<u8>> =
            serde_wasm_bindgen::from_value(witness).map_err(invalid_input)?;
        let hash_bytes = hex::decode(expected_hash_hex).map_err(invalid_input)?;
        let hash: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| wasm_error("INVALID_INPUT", "hash must be 32 bytes"))?;

        self.inner
            .verify_recursive_invariant(&witness_vec, hash)
            .map_err(to_js_error)
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
    wasm_error("CONXIAN_ERROR", &e.to_string())
}

fn invalid_input<E: std::fmt::Display>(e: E) -> JsValue {
    wasm_error("INVALID_INPUT", &e.to_string())
}

const LIGHTNING_INVOICE_MAX_LENGTH: usize = 2048;
const LIGHTNING_INVOICE_TIMESTAMP_DATA_LENGTH: usize = 7;
const LIGHTNING_INVOICE_SIGNATURE_DATA_LENGTH: usize = 104;
const LIGHTNING_PAYMENT_HASH_DATA_LENGTH: usize = 52;

fn validate_lightning_constructor_inputs(
    payment_hash: &str,
    invoice: &str,
    amount_msat: u64,
) -> Result<(), JsValue> {
    if !is_valid_lightning_payment_hash(payment_hash) {
        return Err(wasm_error(
            "INVALID_INPUT",
            "payment_hash must be 32 bytes encoded as 64 hexadecimal characters",
        ));
    }

    if !is_valid_lightning_invoice(invoice) {
        return Err(wasm_error(
            "INVALID_INPUT",
            "invoice must be a valid BOLT11 payment request",
        ));
    }

    if !is_valid_lightning_amount(amount_msat) {
        return Err(wasm_error(
            "INVALID_INPUT",
            "amount_msat must be greater than zero",
        ));
    }

    Ok(())
}

fn is_valid_lightning_payment_hash(payment_hash: &str) -> bool {
    payment_hash.len() == 64
        && payment_hash
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn is_valid_lightning_amount(amount_msat: u64) -> bool {
    amount_msat > 0
}

fn is_valid_lightning_invoice(invoice: &str) -> bool {
    if invoice.is_empty() || invoice.len() > LIGHTNING_INVOICE_MAX_LENGTH {
        return false;
    }

    let Ok(checked) = CheckedHrpstring::new::<Bech32>(invoice) else {
        return false;
    };

    let hrp = checked.hrp().to_string();
    if !is_valid_lightning_invoice_hrp(&hrp) {
        return false;
    }

    let data: Vec<u8> = checked
        .fe32_iter::<std::iter::Empty<u8>>()
        .map(|value| value.to_u8())
        .collect();
    let Some(tagged_data_end) = data
        .len()
        .checked_sub(LIGHTNING_INVOICE_SIGNATURE_DATA_LENGTH)
    else {
        return false;
    };

    if tagged_data_end < LIGHTNING_INVOICE_TIMESTAMP_DATA_LENGTH {
        return false;
    }

    let mut offset = LIGHTNING_INVOICE_TIMESTAMP_DATA_LENGTH;
    let mut payment_hash_fields = 0;
    while offset < tagged_data_end {
        if tagged_data_end - offset < 3 {
            return false;
        }

        let tag = data[offset];
        let field_length = (data[offset + 1] as usize) * 32 + data[offset + 2] as usize;
        offset += 3;

        if field_length > tagged_data_end - offset {
            return false;
        }

        if tag == 1 {
            if field_length != LIGHTNING_PAYMENT_HASH_DATA_LENGTH {
                return false;
            }
            payment_hash_fields += 1;
        }

        offset += field_length;
    }

    offset == tagged_data_end && payment_hash_fields == 1
}

fn is_valid_lightning_invoice_hrp(hrp: &str) -> bool {
    let amount = ["lnbcrt", "lntbs", "lnbc", "lntb", "lnsb"]
        .iter()
        .find_map(|prefix| hrp.strip_prefix(prefix));
    let Some(amount) = amount else {
        return false;
    };

    if amount.is_empty() || amount.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return true;
    }

    if amount.len() < 2 {
        return false;
    }
    let split_at = amount.len() - 1;
    let (digits, multiplier) = amount.split_at(split_at);

    !digits.is_empty()
        && digits.as_bytes().iter().all(|byte| byte.is_ascii_digit())
        && matches!(multiplier, "m" | "u" | "n" | "p")
}

fn legacy_bitvm2_error(operation: crate::UnsupportedOperation) -> JsValue {
    conclave_error_to_js(crate::wasm_support::legacy_bitvm2_unsupported(operation))
}

fn conclave_error_to_js(error: ConclaveError) -> JsValue {
    wasm_error(
        crate::wasm_support::wasm_error_code(&error),
        &error.to_string(),
    )
}

fn wasm_error(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(&format!("{code}: {message}"));
    let _ = js_sys::Reflect::set(
        error.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    error.into()
}

fn unsupported_provider(message: &str) -> JsValue {
    wasm_error("UNSUPPORTED_PROVIDER", message)
}

#[wasm_bindgen]
pub struct WasmFedimintClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::nexus::fedimint::FedimintAdapter,
}

#[wasm_bindgen]
impl WasmFedimintClient {
    pub fn register_federation(&mut self, federation_id: &str) -> Result<(), JsValue> {
        self.inner
            .register_federation(federation_id)
            .map_err(conclave_error_to_js)
    }

    pub fn join_federation(&mut self, invite_code: &str) -> Result<String, JsValue> {
        self.inner
            .join_federation(invite_code)
            .map_err(conclave_error_to_js)
    }

    pub fn prepare_mint_intent(
        &self,
        federation_id: &str,
        amount_sats: u64,
        opaque_handles: JsValue,
    ) -> Result<JsValue, JsValue> {
        let _ = (federation_id, amount_sats, opaque_handles);
        Err(conclave_error_to_js(crate::protocol_unsupported(
            crate::UnsupportedProtocol::Fedimint,
            crate::UnsupportedOperation::Minting,
        )))
    }

    pub fn issue_ecash(
        &self,
        intent: JsValue,
        blinding_handles: JsValue,
        note_handles: JsValue,
    ) -> Result<JsValue, JsValue> {
        let _ = (intent, blinding_handles, note_handles);
        Err(conclave_error_to_js(crate::protocol_unsupported(
            crate::UnsupportedProtocol::Fedimint,
            crate::UnsupportedOperation::Minting,
        )))
    }

    pub fn verify_note(&self, note: JsValue) -> Result<bool, JsValue> {
        let note_obj = serde_wasm_bindgen::from_value(note).map_err(invalid_input)?;
        self.inner
            .verify_note(&note_obj)
            .map_err(conclave_error_to_js)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn fedimint(&self) -> WasmFedimintClient {
        WasmFedimintClient {
            inner: crate::protocol::nexus::fedimint::FedimintAdapter::new(),
        }
    }
}

// ============================================================================
// Lightning LND WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmLightningClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::lightning::LightningPaymentIntent,
}

#[wasm_bindgen]
impl WasmLightningClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        payment_hash: &str,
        invoice: &str,
        amount_msat: u64,
        expiry_secs: Option<u64>,
    ) -> Result<WasmLightningClient, JsValue> {
        validate_lightning_constructor_inputs(payment_hash, invoice, amount_msat)?;
        let intent = crate::protocol::lightning::LightningPaymentIntent::new(
            payment_hash.to_string(),
            invoice.to_string(),
            amount_msat,
            expiry_secs,
        );
        Ok(WasmLightningClient { inner: intent })
    }

    pub fn apply_event(&mut self, event_json: &str) -> Result<(), JsValue> {
        let event: crate::protocol::lightning::LightningEvent =
            serde_json::from_str(event_json).map_err(invalid_input)?;
        self.inner.apply_event(event).map_err(conclave_error_to_js)
    }

    pub fn can_retry(&self) -> bool {
        self.inner.can_retry()
    }

    pub fn get_status(&self) -> String {
        format!("{:?}", self.inner.status)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn lightning(&self) -> WasmLightningClientConstructor {
        WasmLightningClientConstructor
    }
}

#[wasm_bindgen]
pub struct WasmLightningClientConstructor;

#[wasm_bindgen]
impl WasmLightningClientConstructor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmLightningClientConstructor {
        WasmLightningClientConstructor
    }

    pub fn create_intent(
        &self,
        payment_hash: &str,
        invoice: &str,
        amount_msat: u64,
        expiry_secs: Option<u64>,
    ) -> Result<WasmLightningClient, JsValue> {
        WasmLightningClient::new(payment_hash, invoice, amount_msat, expiry_secs)
    }
}

impl Default for WasmLightningClientConstructor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Swap Router WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmSwapRouterClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::swap_router::SwapRouter,
}

// ============================================================================
// DLC WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmDlcClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::dlc::DlcManager,
}

#[wasm_bindgen]
impl WasmDlcClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmDlcClient {
        WasmDlcClient {
            inner: crate::protocol::dlc::DlcManager::new(),
        }
    }

    pub fn generate_contract_id(&self, oracle_announcement: &str, local_collateral: u64) -> String {
        self.inner
            .generate_contract_id(oracle_announcement, local_collateral)
    }

    pub fn offer_contract(
        &self,
        oracle_announcement: &str,
        local_collateral: u64,
        remote_collateral: u64,
    ) -> Result<JsValue, JsValue> {
        let contract = self
            .inner
            .offer_contract(oracle_announcement, local_collateral, remote_collateral)
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&contract).map_err(to_js_error)
    }

    pub fn accept_contract(
        &self,
        contract_json: &str,
        remote_pubkey: &str,
    ) -> Result<JsValue, JsValue> {
        let contract: crate::protocol::dlc::DlcContract =
            serde_json::from_str(contract_json).map_err(invalid_input)?;
        let accepted = self
            .inner
            .accept_contract(contract, remote_pubkey.to_string())
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&accepted).map_err(to_js_error)
    }
}

impl Default for WasmDlcClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn dlc(&self) -> WasmDlcClient {
        WasmDlcClient::new()
    }
}

#[wasm_bindgen]
impl WasmSwapRouterClient {
    #[wasm_bindgen(constructor)]
    pub fn new(gateway_url: &str) -> WasmSwapRouterClient {
        WasmSwapRouterClient {
            inner: crate::protocol::swap_router::SwapRouter::new(
                gateway_url.to_string(),
                reqwest::Client::new(),
            ),
        }
    }

    pub fn gateway_url(&self) -> String {
        self.inner.gateway_url.clone()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn swap_router(&self) -> WasmSwapRouterClient {
        WasmSwapRouterClient {
            inner: crate::protocol::swap_router::SwapRouter::new(
                "https://gateway.conxian-labs.com".to_string(),
                reqwest::Client::new(),
            ),
        }
    }
}

// ============================================================================
// Solver WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmSolverClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::solver::SolverManager,
}

#[wasm_bindgen]
impl WasmSolverClient {
    pub fn new() -> WasmSolverClient {
        WasmSolverClient {
            inner: crate::protocol::solver::SolverManager,
        }
    }

    pub fn rank_bids(&self, bids_json: &str) -> Result<JsValue, JsValue> {
        let bids: Vec<crate::protocol::solver::SolverBid> =
            serde_json::from_str(bids_json).map_err(invalid_input)?;
        let ranked =
            crate::protocol::solver::SolverManager::rank_bids(bids).map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&ranked).map_err(to_js_error)
    }
}

impl Default for WasmSolverClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn solver(&self) -> WasmSolverClient {
        WasmSolverClient::new()
    }
}

// ============================================================================
// ZKML WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmZkmlClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::zkml::ZkmlService,
}

#[wasm_bindgen]
impl WasmZkmlClient {
    #[wasm_bindgen(constructor)]
    pub fn new(gateway_url: &str) -> WasmZkmlClient {
        WasmZkmlClient {
            inner: crate::protocol::zkml::ZkmlService::new(
                gateway_url.to_string(),
                reqwest::Client::new(),
            ),
        }
    }

    pub fn gateway_url(&self) -> String {
        self.inner.gateway_url.clone()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn zkml(&self) -> WasmZkmlClient {
        WasmZkmlClient {
            inner: crate::protocol::zkml::ZkmlService::new(
                "https://gateway.conxian-labs.com".to_string(),
                reqwest::Client::new(),
            ),
        }
    }
}

// ============================================================================
// BitVM2 Orchestrator WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmBitVm2Orchestrator {
    #[wasm_bindgen(skip)]
    pub inner: Arc<std::cell::RefCell<crate::protocol::bitvm2::BitVm2Orchestrator>>,
}

#[wasm_bindgen]
impl WasmBitVm2Orchestrator {
    #[cfg(feature = "development-simulators")]
    fn from_enclave(enclave: Arc<dyn EnclaveManager>) -> WasmBitVm2Orchestrator {
        let ark = Arc::new(crate::protocol::ark::ArkManager::new(enclave.clone()));
        let bitvm = Arc::new(crate::protocol::bitvm::BitVmManager::new(enclave));
        WasmBitVm2Orchestrator {
            inner: Arc::new(std::cell::RefCell::new(
                crate::protocol::bitvm2::BitVm2Orchestrator::new(ark, bitvm),
            )),
        }
    }

    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmBitVm2Orchestrator, JsValue> {
        Err(unsupported_provider(
            "no verified opaque-key provider adapter is registered",
        ))
    }

    #[cfg(feature = "development-simulators")]
    pub fn new_for_development() -> Result<WasmBitVm2Orchestrator, JsValue> {
        let enclave = Arc::new(
            crate::enclave::cloud::CloudEnclave::new_for_development(
                "http://localhost".to_string(),
            )
            .map_err(to_js_error)?,
        );
        Ok(Self::from_enclave(enclave))
    }

    pub fn create_forfeit_with_commitment(
        &self,
        vutxo_json: &str,
        tree_json: &str,
        state_hash_hex: &str,
        taproot_internal_key_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let vutxo: crate::protocol::ark::VUtxoDescriptor =
            serde_json::from_str(vutxo_json).map_err(invalid_input)?;
        let tree: crate::protocol::ark::VtxoTreeNode =
            serde_json::from_str(tree_json).map_err(invalid_input)?;

        let state_hash = hex::decode(state_hash_hex)
            .map_err(invalid_input)?
            .try_into()
            .map_err(|_| wasm_error("INVALID_INPUT", "state hash must be 32 bytes"))?;

        let taproot_internal_key = hex::decode(taproot_internal_key_hex)
            .map_err(invalid_input)?
            .try_into()
            .map_err(|_| {
                wasm_error(
                    "INVALID_INPUT",
                    "taproot internal public key must be 32 bytes",
                )
            })?;

        let forfeit = self
            .inner
            .borrow()
            .create_forfeit_with_commitment(vutxo, tree, state_hash, taproot_internal_key)
            .map_err(conclave_error_to_js)?;

        serde_wasm_bindgen::to_value(&forfeit).map_err(to_js_error)
    }

    pub fn post_commitment(&self, commitment_json: &str) -> Result<String, JsValue> {
        let commitment: crate::protocol::bitvm2::BitVm2Commitment =
            serde_json::from_str(commitment_json).map_err(invalid_input)?;
        self.inner
            .borrow_mut()
            .post_commitment(commitment)
            .map_err(conclave_error_to_js)
    }

    pub fn challenge_commitment(
        &self,
        commitment_id: &str,
        response_json: &str,
    ) -> Result<(), JsValue> {
        let response: crate::protocol::bitvm2::BitVm2ChallengeResponse =
            serde_json::from_str(response_json).map_err(invalid_input)?;
        self.inner
            .borrow_mut()
            .challenge_commitment(commitment_id, response)
            .map_err(conclave_error_to_js)
    }

    pub fn resolve_challenge(
        &self,
        commitment_id: &str,
        operator_punished: bool,
        block_height: u64,
    ) -> Result<(), JsValue> {
        self.inner
            .borrow_mut()
            .resolve_challenge(commitment_id, operator_punished, block_height)
            .map_err(conclave_error_to_js)
    }

    pub fn get_status(&self, commitment_id: &str) -> Result<JsValue, JsValue> {
        let status = self
            .inner
            .borrow()
            .get_challenge_status(commitment_id)
            .map_err(conclave_error_to_js)?;
        serde_wasm_bindgen::to_value(&status).map_err(to_js_error)
    }

    pub fn within_challenge_window(
        &self,
        commitment_id: &str,
        current_block: u64,
    ) -> Result<bool, JsValue> {
        self.inner
            .borrow()
            .is_within_challenge_window(commitment_id, current_block)
            .map_err(conclave_error_to_js)
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn bitvm2(&self) -> Result<WasmBitVm2Orchestrator, JsValue> {
        WasmBitVm2Orchestrator::new()
    }
}

// ============================================================================
// MMR WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmMmrClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::mmr::MmrService,
}

#[wasm_bindgen]
impl WasmMmrClient {
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: &str) -> WasmMmrClient {
        WasmMmrClient {
            inner: crate::protocol::mmr::MmrService::new(
                base_url.to_string(),
                reqwest::Client::new(),
            ),
        }
    }

    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn mmr(&self) -> WasmMmrClient {
        WasmMmrClient::new("https://gateway.conxian-labs.com")
    }
}

// ============================================================================
// Business WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmBusinessClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::business::BusinessRegistry,
}

#[wasm_bindgen]
impl WasmBusinessClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmBusinessClient {
        WasmBusinessClient {
            inner: crate::protocol::business::BusinessRegistry::new(),
        }
    }

    pub fn is_active(&self, business_id: &str) -> bool {
        self.inner.is_active(business_id)
    }

    pub fn get_business(&self, business_id: &str) -> Result<JsValue, JsValue> {
        let profile = self.inner.get_business(business_id);
        match profile {
            Some(p) => serde_wasm_bindgen::to_value(&p).map_err(to_js_error),
            None => Err(JsValue::from_str("Business not found")),
        }
    }

    pub fn register_business(&self, profile_json: &str) -> Result<(), JsValue> {
        let profile: crate::protocol::business::BusinessProfile =
            serde_json::from_str(profile_json).map_err(invalid_input)?;
        self.inner.register_business(profile);
        Ok(())
    }
}

impl Default for WasmBusinessClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn business(&self) -> WasmBusinessClient {
        WasmBusinessClient::new()
    }
}

// ============================================================================
// Settlement Service WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmSettlementClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::settlement_service::ConclaveSettlementService,
}

#[wasm_bindgen]
impl WasmSettlementClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmSettlementClient {
        use crate::protocol::asset::AssetRegistry;
        WasmSettlementClient {
            inner: crate::protocol::settlement_service::ConclaveSettlementService::new(
                std::sync::Arc::new(AssetRegistry::new()),
            ),
        }
    }

    pub fn resolve_trust_tier(&self, source: &str) -> String {
        let trigger_source = match source {
            "iso20022" => crate::protocol::settlement::TriggerSource::Iso20022,
            "papss" => crate::protocol::settlement::TriggerSource::Papss,
            "brics" => crate::protocol::settlement::TriggerSource::Brics,
            _ => return "Unknown".to_string(),
        };
        format!("{:?}", self.inner.resolve_trust_tier(&trigger_source))
    }
}

impl Default for WasmSettlementClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn settlement(&self) -> WasmSettlementClient {
        WasmSettlementClient::new()
    }
}

// ============================================================================
// Stablecoin Orchestrator WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmStablecoinClient {
    #[wasm_bindgen(skip)]
    pub inner: crate::protocol::stablecoin_orchestrator::StablecoinOrchestrator,
}

#[wasm_bindgen]
impl WasmStablecoinClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmStablecoinClient {
        use crate::protocol::asset::AssetRegistry;
        WasmStablecoinClient {
            inner: crate::protocol::stablecoin_orchestrator::StablecoinOrchestrator::new(
                std::sync::Arc::new(AssetRegistry::new()),
            ),
        }
    }
}

impl Default for WasmStablecoinClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn stablecoin(&self) -> WasmStablecoinClient {
        WasmStablecoinClient::new()
    }
}

// ============================================================================
// Opportunity WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmOpportunityClient {
    #[wasm_bindgen(skip)]
    pub _phantom: std::marker::PhantomData<()>,
}

#[wasm_bindgen]
impl WasmOpportunityClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmOpportunityClient {
        WasmOpportunityClient {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Default for WasmOpportunityClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn opportunity(&self) -> WasmOpportunityClient {
        WasmOpportunityClient::new()
    }
}

// ============================================================================
// A2P WASM Bindings
// ============================================================================

#[wasm_bindgen]
pub struct WasmA2PClient;

#[wasm_bindgen]
impl WasmA2PClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmA2PClient {
        WasmA2PClient
    }
}

impl Default for WasmA2PClient {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ConclaveWasmClient {
    pub fn a2p(&self) -> WasmA2PClient {
        WasmA2PClient::new()
    }
}

#[cfg(test)]
mod lightning_wasm_boundary_tests {
    use super::*;

    const MALFORMED_LIGHTNING_INVOICE: &str =
        "lnbc1qqqqqqqpp5ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppwdp039";

    const MALFORMED_LIGHTNING_INVOICE_WITH_EXTRA_FIELDS: &str =
        "lnbc1qqqqqqqpp5ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppwdp039";

    fn valid_lightning_invoice() -> String {
        let charset = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let hrp = b"lnbc";
        let mut data = vec![0u8; 7];
        data.extend([1, 1, 20]);
        data.extend(std::iter::repeat(1u8).take(52));
        data.extend(std::iter::repeat(1u8).take(104));

        let mut values = Vec::with_capacity(hrp.len() * 2 + data.len() + 7);
        values.extend(hrp.iter().map(|byte| (*byte as u32) >> 5));
        values.push(0);
        values.extend(hrp.iter().map(|byte| (*byte as u32) & 31));
        values.extend(data.iter().map(|value| *value as u32));
        values.extend(std::iter::repeat(0u32).take(6));

        let mut checksum = 1u32;
        for value in values {
            let top = checksum >> 25;
            checksum = ((checksum & 0x1ffffff) << 5) ^ value;
            for (index, generator) in generators.iter().enumerate() {
                if (top >> index) & 1 != 0 {
                    checksum ^= generator;
                }
            }
        }
        checksum ^= 1;

        let mut invoice = String::from("lnbc1");
        for value in data {
            invoice.push(charset[value as usize] as char);
        }
        for index in 0..6 {
            let value = (checksum >> (5 * (5 - index))) & 31;
            invoice.push(charset[value as usize] as char);
        }
        invoice
    }

    #[test]
    fn accepts_valid_lightning_constructor_fields() {
        assert!(is_valid_lightning_payment_hash(&"11".repeat(32)));
        assert!(is_valid_lightning_invoice(&valid_lightning_invoice()));
        assert!(is_valid_lightning_amount(1));
    }

    #[test]
    fn rejects_malformed_lightning_constructor_fields() {
        assert!(!is_valid_lightning_payment_hash("payment-hash"));
        assert!(!is_valid_lightning_payment_hash(&"gg".repeat(32)));
        assert!(!is_valid_lightning_invoice("lnbc1-runtime-evidence"));
        assert!(!is_valid_lightning_invoice(MALFORMED_LIGHTNING_INVOICE));
        assert!(!is_valid_lightning_invoice(
            MALFORMED_LIGHTNING_INVOICE_WITH_EXTRA_FIELDS
        ));
        assert!(!is_valid_lightning_invoice("lnbc1"));
        assert!(!is_valid_lightning_amount(0));
    }
}
