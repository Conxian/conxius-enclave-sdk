use crate::enclave::EnclaveManager;
use crate::protocol::ark::ArkManager;
use crate::protocol::bitvm::BitVmManager;
use crate::protocol::ethereum::EthereumManager;
use crate::protocol::nexus::fedimint::FedimintAdapter;
use crate::protocol::solana::SolanaManager;
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
    pub fn new(enclave_url: &str) -> Result<ConclaveWasmClient, JsValue> {
        let enclave = Arc::new(
            crate::enclave::cloud::CloudEnclave::new(enclave_url.to_string())
                .map_err(to_js_error)?,
        );
        Ok(ConclaveWasmClient { enclave })
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
    pub fn derive_vutxo_key(&self, seed_hex: &str, index: u32) -> Result<String, JsValue> {
        let seed = hex::decode(seed_hex).map_err(to_js_error)?;
        let key = self.inner.derive_vutxo_key(&seed, index);
        Ok(hex::encode(key))
    }

    pub async fn recovery_scan(
        &self,
        master_seed_hex: &str,
        gap_limit: u32,
        asp_url: &str,
    ) -> Result<JsValue, JsValue> {
        let seed_bytes = hex::decode(master_seed_hex).map_err(to_js_error)?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid seed length"))?;

        let found = self
            .inner
            .recovery_scan(seed, gap_limit, asp_url)
            .await
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&found).map_err(to_js_error)
    }

    pub fn construct_vtxo_tree(&self, leaves: JsValue) -> Result<JsValue, JsValue> {
        let leaves_vec = serde_wasm_bindgen::from_value(leaves).map_err(to_js_error)?;
        let root = self
            .inner
            .construct_vtxo_tree(leaves_vec)
            .map_err(to_js_error)?;
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

    pub fn aggregate_challenge_signatures(
        &self,
        pubkeys_hex: JsValue,
        pub_nonces_hex: JsValue,
        partial_sigs_hex: JsValue,
        challenge: JsValue,
    ) -> Result<JsValue, JsValue> {
        let pks: Vec<String> = serde_wasm_bindgen::from_value(pubkeys_hex).map_err(to_js_error)?;
        let nonces: Vec<String> =
            serde_wasm_bindgen::from_value(pub_nonces_hex).map_err(to_js_error)?;
        let sigs: Vec<String> =
            serde_wasm_bindgen::from_value(partial_sigs_hex).map_err(to_js_error)?;
        let chal = serde_wasm_bindgen::from_value(challenge).map_err(to_js_error)?;

        let mut pks_decoded = Vec::new();
        for pk in pks {
            let bytes = hex::decode(pk).map_err(to_js_error)?;
            pks_decoded.push(secp256k1::PublicKey::from_slice(&bytes).map_err(to_js_error)?);
        }

        let mut nonces_decoded = Vec::new();
        for n in nonces {
            let bytes = hex::decode(n).map_err(to_js_error)?;
            nonces_decoded.push(musig2::PubNonce::from_slice(&bytes).map_err(to_js_error)?);
        }

        let mut sigs_decoded = Vec::new();
        for s in sigs {
            let bytes = hex::decode(s).map_err(to_js_error)?;
            sigs_decoded.push(musig2::PartialSignature::from_slice(&bytes).map_err(to_js_error)?);
        }

        let aggregate = self
            .inner
            .aggregate_challenge_signatures(&pks_decoded, nonces_decoded, sigs_decoded, chal)
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&aggregate).map_err(to_js_error)
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
        Ok(EthereumManager::new(self.enclave.as_ref()).prepare_erc20_transfer(transfer))
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

    pub fn verify_recursive_invariant(
        &self,
        witness: JsValue,
        expected_hash_hex: &str,
    ) -> Result<bool, JsValue> {
        let witness_vec: Vec<Vec<u8>> =
            serde_wasm_bindgen::from_value(witness).map_err(to_js_error)?;
        let hash_bytes = hex::decode(expected_hash_hex).map_err(to_js_error)?;
        let hash: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid hash length"))?;

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
    JsValue::from_str(&e.to_string())
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
            .map_err(to_js_error)
    }

    pub fn join_federation(&mut self, invite_code: &str) -> Result<String, JsValue> {
        self.inner.join_federation(invite_code).map_err(to_js_error)
    }

    pub fn prepare_mint_intent(
        &self,
        federation_id: &str,
        amount_sats: u64,
        secrets: JsValue,
    ) -> Result<JsValue, JsValue> {
        let secrets_vec: Vec<String> =
            serde_wasm_bindgen::from_value(secrets).map_err(to_js_error)?;
        let secrets_refs: Vec<&str> = secrets_vec.iter().map(|s| s.as_str()).collect();
        let (intent, bf) = self
            .inner
            .prepare_mint_intent(federation_id, amount_sats, secrets_refs)
            .map_err(to_js_error)?;

        let res = serde_json::json!({
            "intent": intent,
            "blinding_factors": bf
        });
        serde_wasm_bindgen::to_value(&res).map_err(to_js_error)
    }

    pub fn issue_ecash(
        &self,
        intent: JsValue,
        blinding_factors: JsValue,
        original_secrets: JsValue,
    ) -> Result<JsValue, JsValue> {
        let intent_obj = serde_wasm_bindgen::from_value(intent).map_err(to_js_error)?;
        let bf_obj = serde_wasm_bindgen::from_value(blinding_factors).map_err(to_js_error)?;
        let secrets_obj = serde_wasm_bindgen::from_value(original_secrets).map_err(to_js_error)?;

        let ecash = self
            .inner
            .issue_ecash(intent_obj, bf_obj, secrets_obj)
            .map_err(to_js_error)?;
        serde_wasm_bindgen::to_value(&ecash).map_err(to_js_error)
    }

    pub fn verify_note(&self, note: JsValue) -> Result<bool, JsValue> {
        let note_obj = serde_wasm_bindgen::from_value(note).map_err(to_js_error)?;
        Ok(self.inner.verify_note(&note_obj))
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
