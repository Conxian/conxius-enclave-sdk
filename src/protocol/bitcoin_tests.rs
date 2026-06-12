#[cfg(test)]
mod tests {
    use super::super::bitcoin::BitcoinManager;
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::bitcoin::{
        BitcoinTransactionIntent, FeeBumpStrategy, MempoolPolicy, TransactionState,
    };
    use std::sync::Arc;

    #[test]
    fn test_bitcoin_manager_descriptors() -> crate::ConclaveResult<()> {
        let enclave = Arc::new(CloudEnclave::new(
            "https://vault.conxian-labs.com".to_string(),
        )?);
        let mgr = BitcoinManager::new(enclave);

        let wpkh = mgr.generate_wpkh_descriptor("m/84'/0'/0'/0/0")?;
        assert!(wpkh.starts_with("wpkh("));

        let tr = mgr.generate_tr_descriptor("m/86'/0'/0'/0/0")?;
        assert!(tr.starts_with("tr("));

        Ok(())
    }

    #[test]
    fn test_bitcoin_transaction_intent_lifecycle() {
        let policy = MempoolPolicy::default_sovereign();
        assert_eq!(policy.fee_bump_strategy, FeeBumpStrategy::RBF);

        let mut intent =
            BitcoinTransactionIntent::new("txid123".to_string(), vec![1, 2, 3], policy);

        assert_eq!(intent.state, TransactionState::Unconfirmed);

        intent.update_state(TransactionState::Confirmed {
            height: 100,
            timestamp: 123456,
        });
        if let TransactionState::Confirmed { height, .. } = intent.state {
            assert_eq!(height, 100);
        } else {
            panic!("Expected Confirmed state");
        }
    }
}
