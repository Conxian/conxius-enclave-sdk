#[cfg(test)]
mod tests {
    use crate::enclave::cloud::CloudEnclave;
    use crate::protocol::economy::{DualStackIntent, YieldEngine};

    #[test]
    fn test_dual_stack_generation_fails_closed_without_provider() {
        let enclave = CloudEnclave::new("https://vault.conxian-labs.com".to_string()).unwrap();
        let engine = YieldEngine::new(&enclave);

        let intent = DualStackIntent {
            amount_sbtc: 1000000,
            amount_stx: 5000000,
            lock_period: 10,
        };

        assert!(engine.dual_stack(intent).is_err());
    }

    #[test]
    fn test_gas_sponsored_tx_generation_fails_closed_without_provider() {
        let enclave = CloudEnclave::new("https://vault.conxian-labs.com".to_string()).unwrap();
        let engine = YieldEngine::new(&enclave);

        let intent = crate::protocol::economy::GasFeeIntent {
            tx_payload: vec![1, 2, 3],
            estimated_fee_sbtc: 100,
        };

        assert!(engine.prepare_gas_sponsored_tx(intent).is_err());
    }
}
