use crate::protocol::asset::validate_evm_address;
use crate::{ConclaveError, ConclaveResult};
use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAccountAction {
    pub target: String,
    pub value: String,
    pub call_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC7579Execution {
    pub execution_mode: [u8; 32],
    pub actions: Vec<SmartAccountAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModuleType {
    Validator = 1,
    Executor = 2,
    Fallback = 3,
    Hook = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub module_type: ModuleType,
    pub module_address: String,
    pub init_data: Vec<u8>,
}

pub struct ModularAccountManager {
    // Management of ERC-7579 modules and plugins
}

impl Default for ModularAccountManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ModularAccountManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Validates a batch without claiming that it is executable by a particular
    /// account. The account, chain, module, and entry-point provenance are not
    /// available in this crate, so `prepare_execution` remains disabled.
    pub fn prepare_execution(
        &self,
        actions: Vec<SmartAccountAction>,
    ) -> ConclaveResult<ERC7579Execution> {
        self.validate_actions(&actions)?;
        Err(ConclaveError::Unsupported(
            "ERC-7579 execution requires a network-bound account, entry-point, and module registry"
                .to_string(),
        ))
    }

    /// Validates action encoding and rejects no-op or malformed value-bearing calls.
    pub fn validate_actions(&self, actions: &[SmartAccountAction]) -> ConclaveResult<()> {
        if actions.is_empty() {
            return Err(ConclaveError::InvalidConfiguration(
                "ERC-7579 execution requires at least one action".to_string(),
            ));
        }
        if actions.len() > 128 {
            return Err(ConclaveError::InvalidConfiguration(
                "ERC-7579 execution batch exceeds the supported action limit".to_string(),
            ));
        }

        for action in actions {
            let target = validate_evm_address(&action.target)?;
            if target == Address::ZERO {
                return Err(ConclaveError::InvalidConfiguration(
                    "ERC-7579 action target cannot be the zero address".to_string(),
                ));
            }

            let value = action.value.parse::<U256>().map_err(|_| {
                ConclaveError::InvalidConfiguration(
                    "ERC-7579 action value must be a non-negative integer".to_string(),
                )
            })?;
            if value.is_zero() && action.call_data.is_empty() {
                return Err(ConclaveError::InvalidConfiguration(
                    "ERC-7579 action cannot be an empty zero-value call".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Performs local module-shape validation only. It intentionally does not
    /// establish ERC-7579 interface support or code provenance.
    pub fn validate_module_config(&self, config: &ModuleConfig) -> ConclaveResult<()> {
        let module_address = validate_evm_address(&config.module_address)?;
        if module_address == Address::ZERO {
            return Err(ConclaveError::InvalidConfiguration(
                "ERC-7579 module address cannot be the zero address".to_string(),
            ));
        }
        if config.init_data.is_empty() {
            return Err(ConclaveError::InvalidConfiguration(
                "ERC-7579 module initialization data is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Fails closed until a canonical, network-bound module registry and
    /// ERC-7579 interface/provenance verifier are supplied.
    pub fn validate_module_setup(&self, config: &ModuleConfig) -> ConclaveResult<()> {
        self.validate_module_config(config)?;
        Err(ConclaveError::Unsupported(
            "ERC-7579 module compatibility and provenance require on-chain verification"
                .to_string(),
        ))
    }

    pub fn validate_module_setup_on_network(
        &self,
        config: &ModuleConfig,
        chain_id: u64,
    ) -> ConclaveResult<()> {
        if chain_id == 0 {
            return Err(ConclaveError::InvalidConfiguration(
                "ERC-7579 module validation requires a non-zero EVM chain ID".to_string(),
            ));
        }
        self.validate_module_setup(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EVM_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

    fn valid_action() -> SmartAccountAction {
        SmartAccountAction {
            target: TEST_EVM_ADDRESS.to_string(),
            value: "1".to_string(),
            call_data: Vec::new(),
        }
    }

    #[test]
    fn canonical_action_shape_is_validated_without_execution_claim() {
        let manager = ModularAccountManager::new();
        assert!(manager.validate_actions(&[valid_action()]).is_ok());
        assert!(matches!(
            manager.prepare_execution(vec![valid_action()]),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_action_is_rejected_before_value_bearing_path() {
        let manager = ModularAccountManager::new();
        let mut action = valid_action();
        action.target = "not-an-evm-address".to_string();

        assert!(matches!(
            manager.validate_actions(&[action]),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn module_setup_requires_provenance_after_local_validation() {
        let manager = ModularAccountManager::new();
        let config = ModuleConfig {
            module_type: ModuleType::Validator,
            module_address: TEST_EVM_ADDRESS.to_string(),
            init_data: vec![1],
        };

        assert!(manager.validate_module_config(&config).is_ok());
        assert!(matches!(
            manager.validate_module_setup_on_network(&config, 1),
            Err(ConclaveError::Unsupported(_))
        ));
    }

    #[test]
    fn module_network_context_cannot_be_zero() {
        let manager = ModularAccountManager::new();
        let config = ModuleConfig {
            module_type: ModuleType::Executor,
            module_address: TEST_EVM_ADDRESS.to_string(),
            init_data: vec![1],
        };

        assert!(matches!(
            manager.validate_module_setup_on_network(&config, 0),
            Err(ConclaveError::InvalidConfiguration(_))
        ));
    }
}
