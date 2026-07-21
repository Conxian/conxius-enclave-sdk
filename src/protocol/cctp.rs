use crate::protocol::asset::validate_evm_address;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CctpTransferIntent {
    pub amount: u128,
    pub source_chain: u32,
    pub destination_chain: u32,
    pub mint_recipient: String,
    pub burn_token: String,
}

pub struct CctpManager {
    // Circle Cross-Chain Transfer Protocol Orchestration
}

// Circle domain identifiers are not public chain IDs. This conservative list
// covers the reviewed V1/V2 domains used by the local validation boundary;
// calldata and attestation verification remain disabled below.
const REVIEWED_CCTP_DOMAINS: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 25, 26, 27, 28,
    29, 30, 31,
];

impl Default for CctpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CctpManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn validate_intent(&self, intent: &CctpTransferIntent) -> ConclaveResult<()> {
        if intent.amount == 0 {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP transfer amount must be non-zero".to_string(),
            ));
        }
        if !REVIEWED_CCTP_DOMAINS.contains(&intent.source_chain)
            || !REVIEWED_CCTP_DOMAINS.contains(&intent.destination_chain)
        {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP source and destination must use reviewed Circle domain identifiers"
                    .to_string(),
            ));
        }
        if intent.source_chain == intent.destination_chain {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP source and destination domains must differ".to_string(),
            ));
        }

        let burn_token = validate_evm_address(&intent.burn_token)?;
        if burn_token.is_zero() {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP burn token cannot be the zero address".to_string(),
            ));
        }

        let recipient = intent.mint_recipient.strip_prefix("0x").ok_or_else(|| {
            ConclaveError::InvalidConfiguration(
                "CCTP mint recipient must be a 32-byte 0x-prefixed value".to_string(),
            )
        })?;
        if recipient.len() != 64
            || !recipient
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP mint recipient must be a 32-byte 0x-prefixed value".to_string(),
            ));
        }
        if recipient.bytes().all(|byte| byte == b'0') {
            return Err(ConclaveError::InvalidConfiguration(
                "CCTP mint recipient cannot be the zero value".to_string(),
            ));
        }

        Ok(())
    }

    /// CCTP calldata and Iris attestation verification are disabled until the
    /// SDK carries a reviewed Circle domain/token-messenger registry and a
    /// canonical signature verifier. Returning an empty payload or accepting a
    /// non-empty attestation would be an unsafe authorization shortcut.
    pub fn prepare_burn_payload(&self, intent: CctpTransferIntent) -> ConclaveResult<Vec<u8>> {
        self.validate_intent(&intent)?;
        Err(ConclaveError::Unsupported(
            "CCTP burn encoding is disabled until canonical Circle network metadata and ABI vectors are verified"
                .to_string(),
        ))
    }

    pub fn verify_attestation(&self, payload: &[u8], attestation: &[u8]) -> ConclaveResult<bool> {
        if payload.is_empty() || attestation.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        Err(ConclaveError::Unsupported(
            "CCTP attestation verification is disabled until canonical Iris signature and payload binding verification is available"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BURN_TOKEN: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const TEST_RECIPIENT: &str =
        "0x00000000000000000000000052908400098527886E0F7030069857D2E4169EE7";

    fn valid_intent() -> CctpTransferIntent {
        CctpTransferIntent {
            amount: 1,
            source_chain: 0,
            destination_chain: 6,
            mint_recipient: TEST_RECIPIENT.to_string(),
            burn_token: TEST_BURN_TOKEN.to_string(),
        }
    }

    #[test]
    fn canonical_intent_shape_passes_local_validation() {
        let manager = CctpManager::new();
        assert!(manager.validate_intent(&valid_intent()).is_ok());
        assert!(matches!(
            manager.prepare_burn_payload(valid_intent()),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_network_or_recipient_data_is_rejected() {
        let manager = CctpManager::new();
        let mut intent = valid_intent();
        intent.source_chain = intent.destination_chain;
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));

        let mut intent = valid_intent();
        intent.destination_chain = 999;
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));

        let mut intent = valid_intent();
        intent.mint_recipient = "not-a-bytes32-recipient".to_string();
        assert!(matches!(
            manager.validate_intent(&intent),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn unbound_attestation_cannot_authorize_payload() {
        let manager = CctpManager::new();
        assert!(matches!(
            manager.verify_attestation(b"payload", b"attestation"),
            Err(ConclaveError::Unsupported(_))
        ));
        assert!(matches!(
            manager.verify_attestation(b"", b"attestation"),
            Err(ConclaveError::InvalidPayload)
        ));
    }
}
