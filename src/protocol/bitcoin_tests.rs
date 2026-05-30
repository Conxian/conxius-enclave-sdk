#[cfg(test)]
mod tests {
    use super::super::bitcoin::BitcoinManager;
    use crate::enclave::cloud::CloudEnclave;
    use std::sync::Arc;

    #[test]
    fn test_bitcoin_manager_descriptors() -> crate::ConclaveResult<()> {
        let enclave = Arc::new(CloudEnclave::new("https://vault.conxian-labs.com".to_string())?);
        let mgr = BitcoinManager::new(enclave);

        let wpkh = mgr.generate_wpkh_descriptor("m/84'/0'/0'/0/0")?;
        assert!(wpkh.starts_with("wpkh("));

        let tr = mgr.generate_tr_descriptor("m/86'/0'/0'/0/0")?;
        assert!(tr.starts_with("tr("));

        Ok(())
    }
}
