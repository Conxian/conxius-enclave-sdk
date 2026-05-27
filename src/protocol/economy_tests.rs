#[cfg(test)]
mod tests {
    use crate::protocol::economy::{YieldEngine, DualStackIntent};
    use crate::enclave::cloud::CloudEnclave;

    #[test]
    fn test_dual_stack_generation() {
        let enclave = CloudEnclave::new("https://vault.conxian.io".to_string()).unwrap();
        let engine = YieldEngine::new(&enclave);

        let intent = DualStackIntent {
            amount_sbtc: 1000000,
            amount_stx: 5000000,
            lock_period: 10,
        };

        let (sig, post_conditions) = engine.dual_stack(intent).unwrap();
        assert!(!sig.is_empty());
        assert_eq!(post_conditions.len(), 2);
    }

    #[test]
    fn test_gas_sponsored_tx_generation() {
        let enclave = CloudEnclave::new("https://vault.conxian.io".to_string()).unwrap();
        let engine = YieldEngine::new(&enclave);

        let intent = crate::protocol::economy::GasFeeIntent {
            tx_payload: vec![1, 2, 3],
            estimated_fee_sbtc: 100,
        };

        let sig = engine.prepare_gas_sponsored_tx(intent).unwrap();
        assert!(!sig.is_empty());
    }

}
