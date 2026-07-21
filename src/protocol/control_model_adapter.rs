//! Cycle-safe serialized adapters for the Core control-model contracts.
//!
//! `lib-conxian-core` remains canonical for the shared control-model taxonomy
//! and wire shapes. This module mirrors only the reviewed serialized surface
//! needed by the SDK while the current Core feature graph still points
//! optionally at this SDK. It must not acquire a dependency on Core: doing so
//! would create a Cargo cycle.
//!
//! The Core-compatible DTOs in this module are intentionally available on the
//! always-on adapter surface, independent of the `bip110_compliant` feature.
//! That feature gates executable SDK validation in [`crate::protocol::bip110`];
//! it does not gate serialized wire compatibility.

use crate::config::Network;
use crate::protocol::asset::Chain;
use crate::protocol::rails::TrustTier;
use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

/// Core's canonical trust taxonomy.
///
/// The serialized names and policy meaning mirror
/// `lib-conxian-core/src/control_model/trust.rs`. This is a wire-boundary
/// adapter, not a second canonical trust implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreTrustTier {
    Strict,
    Managed,
    Expedient,
    ObserverOnly,
}

impl CoreTrustTier {
    /// Mirrors Core's production eligibility check for the shared taxonomy.
    pub const fn is_production_allowed(self) -> bool {
        !matches!(self, Self::ObserverOnly)
    }

    /// Mirrors Core's exact invariant for the strict trust tier.
    pub const fn requires_light_client(self) -> bool {
        matches!(self, Self::Strict)
    }
}

/// Converts an SDK rail tier to Core's representation only.
///
/// This mapping preserves wire compatibility and does not authorize a
/// production rail. Use [`project_production_rail_policy`] for the fallible
/// production boundary.
pub const fn sdk_trust_tier_to_core_representation(value: TrustTier) -> CoreTrustTier {
    match value {
        TrustTier::T1 => CoreTrustTier::Strict,
        TrustTier::T2 => CoreTrustTier::Managed,
        TrustTier::T3 => CoreTrustTier::Expedient,
        TrustTier::T4 => CoreTrustTier::ObserverOnly,
    }
}

/// Converts Core's representation back to the existing SDK rail tier only.
///
/// `ObserverOnly` therefore maps to SDK `T4` here by design. This is a
/// representation round trip, not a production authorization decision.
pub const fn core_trust_tier_to_sdk_representation(value: CoreTrustTier) -> TrustTier {
    match value {
        CoreTrustTier::Strict => TrustTier::T1,
        CoreTrustTier::Managed => TrustTier::T2,
        CoreTrustTier::Expedient => TrustTier::T3,
        CoreTrustTier::ObserverOnly => TrustTier::T4,
    }
}

/// Converts a Core trust tier to an SDK rail threshold for production use.
///
/// Unlike the representation-only mapping, this function rejects Core
/// `ObserverOnly` before it can become SDK `T4` as a production minimum.
pub fn core_trust_tier_to_sdk_production(value: CoreTrustTier) -> ConclaveResult<TrustTier> {
    if !value.is_production_allowed() {
        return Err(ConclaveError::Unsupported(
            "Core ObserverOnly cannot become a production SDK rail threshold".to_string(),
        ));
    }

    Ok(core_trust_tier_to_sdk_representation(value))
}

/// Core's exact verification-class wire enum.
///
/// The variant names and `snake_case` serde values mirror
/// `lib-conxian-core/src/control_model/trust.rs` at the reviewed baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreVerificationClass {
    LightClient,
    ExternalQuorum,
    AppDefinedMultiVerifier,
    SharedPos,
    NativeObservation,
    ZkVerified,
}

/// Core's reviewed concrete-chain taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreChain {
    Bitcoin,
    Stacks,
    Liquid,
    Lightning,
    Babylon,
    Bob,
    Mezo,
    Citrea,
    Botanix,
    Ethereum,
    Base,
    Arbitrum,
    Optimism,
    Polygon,
    CosmosHub,
    Osmosis,
    Celestia,
    Solana,
    Eclipse,
    Aptos,
    Sui,
    Polkadot,
    Kusama,
}

impl CoreChain {
    /// Returns Core's canonical family for this exact chain.
    pub const fn family(self) -> CoreChainFamily {
        match self {
            Self::Bitcoin | Self::Stacks | Self::Liquid | Self::Lightning | Self::Babylon => {
                CoreChainFamily::BitcoinUtxo
            }
            Self::Bob
            | Self::Mezo
            | Self::Citrea
            | Self::Botanix
            | Self::Ethereum
            | Self::Base
            | Self::Arbitrum
            | Self::Optimism
            | Self::Polygon => CoreChainFamily::Evm,
            Self::CosmosHub | Self::Osmosis | Self::Celestia => CoreChainFamily::CosmosIbc,
            Self::Solana | Self::Eclipse => CoreChainFamily::SolanaSvm,
            Self::Aptos | Self::Sui => CoreChainFamily::Move,
            Self::Polkadot | Self::Kusama => CoreChainFamily::Substrate,
        }
    }
}

/// Core's reviewed chain-family taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreChainFamily {
    BitcoinUtxo,
    Evm,
    CosmosIbc,
    SolanaSvm,
    Move,
    Substrate,
}

/// Maps only SDK chains that are exact current Core concrete-chain values.
///
/// SDK-only chains, generic chain aliases, and values that would lose
/// concrete-chain identity are rejected rather than collapsed to a family.
pub fn sdk_chain_to_core(value: Chain) -> ConclaveResult<CoreChain> {
    let mapped = match value {
        Chain::BITCOIN => CoreChain::Bitcoin,
        Chain::STACKS => CoreChain::Stacks,
        Chain::LIQUID => CoreChain::Liquid,
        Chain::LIGHTNING => CoreChain::Lightning,
        Chain::BABYLON => CoreChain::Babylon,
        Chain::BOB => CoreChain::Bob,
        Chain::MEZO => CoreChain::Mezo,
        Chain::CITREA => CoreChain::Citrea,
        Chain::BOTANIX => CoreChain::Botanix,
        Chain::ETHEREUM => CoreChain::Ethereum,
        Chain::BASE => CoreChain::Base,
        Chain::ARBITRUM => CoreChain::Arbitrum,
        Chain::OPTIMISM => CoreChain::Optimism,
        Chain::POLYGON => CoreChain::Polygon,
        Chain::SOLANA => CoreChain::Solana,
        Chain::APTOS => CoreChain::Aptos,
        Chain::SUI => CoreChain::Sui,
        unsupported => {
            return Err(ConclaveError::Unsupported(format!(
                "SDK chain {unsupported} is not an exact reviewed Core chain"
            )))
        }
    };

    Ok(mapped)
}

/// A fail-closed projection of SDK runtime policy into Core control-model
/// values. `network` is deliberately absent: Core has no equivalent network
/// enum, so the SDK context is validated before this projection is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreProductionRailPolicyProjection {
    pub trust_tier: CoreTrustTier,
    pub verification_class: CoreVerificationClass,
    pub chain: CoreChain,
    pub family: CoreChainFamily,
}

/// Validates the only currently reviewed SDK network context for a production
/// Core projection. Testnet and Devnet must not be represented as production
/// Core control-model values.
pub fn validate_production_network_context(network: Network) -> ConclaveResult<()> {
    match network {
        Network::Mainnet => Ok(()),
        Network::Testnet | Network::Devnet => Err(ConclaveError::Unsupported(
            "Core control-model production projection supports Mainnet only".to_string(),
        )),
    }
}

/// Applies Core's production trust-tier policy to the mirrored wire values.
///
/// Core rejects `ObserverOnly` in production and requires `LightClient` for
/// `Strict`; this adapter keeps both invariants at the SDK authorization
/// boundary instead of treating a representation mapping as authorization.
pub fn validate_core_trust_tier_policy(
    trust_tier: CoreTrustTier,
    verification_class: CoreVerificationClass,
) -> ConclaveResult<()> {
    if !trust_tier.is_production_allowed() {
        return Err(ConclaveError::Unsupported(
            "Core ObserverOnly trust tier is not production-authorized".to_string(),
        ));
    }

    if trust_tier.requires_light_client()
        && verification_class != CoreVerificationClass::LightClient
    {
        return Err(ConclaveError::Unsupported(
            "Core Strict trust tier requires LightClient verification".to_string(),
        ));
    }

    Ok(())
}

/// Projects SDK rail, network, and chain inputs into reviewed Core values.
///
/// This is the fallible production boundary, not a representation-only
/// conversion. It requires the Core verification context, enforces Core's
/// `Strict`/`LightClient` invariant, rejects SDK `T4`/Core `ObserverOnly`, and
/// rejects Testnet, Devnet, and SDK chains without an exact Core counterpart.
pub fn project_production_rail_policy(
    trust_tier: TrustTier,
    verification_class: CoreVerificationClass,
    network: Network,
    chain: Chain,
) -> ConclaveResult<CoreProductionRailPolicyProjection> {
    validate_production_network_context(network)?;

    let core_trust_tier = sdk_trust_tier_to_core_representation(trust_tier);
    validate_core_trust_tier_policy(core_trust_tier, verification_class)?;

    let core_chain = sdk_chain_to_core(chain)?;
    Ok(CoreProductionRailPolicyProjection {
        trust_tier: core_trust_tier,
        verification_class,
        chain: core_chain,
        family: core_chain.family(),
    })
}

/// Core's canonical BIP-110 limits from PR #184.
///
/// This serialized DTO is intentionally always available, independent of the
/// `bip110_compliant` feature. The feature gates executable SDK validation,
/// not the Core-compatible wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreBip110Limits {
    pub max_pushdata_bytes: usize,
    pub max_op_return_bytes: usize,
    pub max_script_pubkey_bytes: usize,
    pub max_witness_element_bytes: usize,
}

impl CoreBip110Limits {
    /// Returns the exact canonical 256/83/34/256 limits.
    pub const fn canonical() -> Self {
        Self {
            max_pushdata_bytes: 256,
            max_op_return_bytes: 83,
            max_script_pubkey_bytes: 34,
            max_witness_element_bytes: 256,
        }
    }
}

impl Default for CoreBip110Limits {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Core's serialized BIP-110 transaction-shape measurements.
///
/// This serialized DTO is intentionally always available, independent of the
/// `bip110_compliant` feature. The feature gates executable SDK validation,
/// not the Core-compatible wire contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreBip110TransactionShape {
    pub pushdata_sizes_bytes: Vec<usize>,
    pub op_return_script_pubkey_sizes_bytes: Vec<usize>,
    pub non_op_return_script_pubkey_sizes_bytes: Vec<usize>,
    pub witness_element_sizes_bytes: Vec<usize>,
}

impl CoreBip110TransactionShape {
    /// Creates a shape using Core's exact field order.
    pub fn new(
        pushdata_sizes_bytes: Vec<usize>,
        op_return_script_pubkey_sizes_bytes: Vec<usize>,
        non_op_return_script_pubkey_sizes_bytes: Vec<usize>,
        witness_element_sizes_bytes: Vec<usize>,
    ) -> Self {
        Self {
            pushdata_sizes_bytes,
            op_return_script_pubkey_sizes_bytes,
            non_op_return_script_pubkey_sizes_bytes,
            witness_element_sizes_bytes,
        }
    }
}

/// Core's signed-envelope descriptor wire shape.
///
/// This adapter exposes deterministic descriptor serialization and identity
/// helpers only. It does not replace SDK signature verification, persistent
/// replay storage, or runtime replay enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreSignedEnvelopeDescriptor {
    pub event_id: String,
    pub sequence: u64,
    pub publisher: String,
    pub payload_hash: String,
    pub commitments: Vec<String>,
}

impl CoreSignedEnvelopeDescriptor {
    /// Returns Core's deterministic replay/idempotency identity format.
    pub fn idempotency_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.publisher.trim(),
            self.event_id.trim(),
            self.sequence
        )
    }

    /// Serializes the descriptor using its stable struct-field order.
    pub fn deterministic_serialized_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Serializes the descriptor using its stable struct-field order.
    pub fn deterministic_serialized_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_trust_tier_uses_exact_snake_case_values() {
        let values = [
            (CoreTrustTier::Strict, r#""strict""#),
            (CoreTrustTier::Managed, r#""managed""#),
            (CoreTrustTier::Expedient, r#""expedient""#),
            (CoreTrustTier::ObserverOnly, r#""observer_only""#),
        ];

        for (value, expected) in values {
            assert_eq!(serde_json::to_string(&value).unwrap(), expected);
            assert_eq!(
                serde_json::from_str::<CoreTrustTier>(expected).unwrap(),
                value
            );
        }
    }

    #[test]
    fn core_chain_and_family_use_exact_reviewed_names() {
        let chains = [
            (CoreChain::Bitcoin, "bitcoin"),
            (CoreChain::Stacks, "stacks"),
            (CoreChain::Liquid, "liquid"),
            (CoreChain::Lightning, "lightning"),
            (CoreChain::Babylon, "babylon"),
            (CoreChain::Bob, "bob"),
            (CoreChain::Mezo, "mezo"),
            (CoreChain::Citrea, "citrea"),
            (CoreChain::Botanix, "botanix"),
            (CoreChain::Ethereum, "ethereum"),
            (CoreChain::Base, "base"),
            (CoreChain::Arbitrum, "arbitrum"),
            (CoreChain::Optimism, "optimism"),
            (CoreChain::Polygon, "polygon"),
            (CoreChain::CosmosHub, "cosmos_hub"),
            (CoreChain::Osmosis, "osmosis"),
            (CoreChain::Celestia, "celestia"),
            (CoreChain::Solana, "solana"),
            (CoreChain::Eclipse, "eclipse"),
            (CoreChain::Aptos, "aptos"),
            (CoreChain::Sui, "sui"),
            (CoreChain::Polkadot, "polkadot"),
            (CoreChain::Kusama, "kusama"),
        ];
        for (value, expected) in chains {
            assert_eq!(
                serde_json::to_string(&value).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<CoreChain>(&format!("\"{expected}\"")).unwrap(),
                value
            );
        }

        let families = [
            (CoreChainFamily::BitcoinUtxo, "bitcoin_utxo"),
            (CoreChainFamily::Evm, "evm"),
            (CoreChainFamily::CosmosIbc, "cosmos_ibc"),
            (CoreChainFamily::SolanaSvm, "solana_svm"),
            (CoreChainFamily::Move, "move"),
            (CoreChainFamily::Substrate, "substrate"),
        ];
        for (value, expected) in families {
            assert_eq!(
                serde_json::to_string(&value).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<CoreChainFamily>(&format!("\"{expected}\"")).unwrap(),
                value
            );
        }
    }

    #[test]
    fn unknown_values_and_fields_fail_closed() {
        assert!(serde_json::from_str::<CoreTrustTier>(r#""t1""#).is_err());
        assert!(serde_json::from_str::<CoreChain>(r#""linea""#).is_err());
        assert!(serde_json::from_str::<CoreBip110Limits>(
            r#"{"max_pushdata_bytes":256,"max_op_return_bytes":83,"max_script_pubkey_bytes":34,"max_witness_element_bytes":256,"extra":0}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CoreBip110TransactionShape>(
            r#"{"pushdata_sizes_bytes":[],"op_return_script_pubkey_sizes_bytes":[],"non_op_return_script_pubkey_sizes_bytes":[],"witness_element_sizes_bytes":[],"extra":[]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CoreBip110Limits>(
            r#"{"max_pushdata_bytes":"256","max_op_return_bytes":83,"max_script_pubkey_bytes":34,"max_witness_element_bytes":256}"#
        )
        .is_err());
    }

    #[test]
    fn sdk_trust_tier_mapping_is_explicit_and_production_rejects_t4() {
        assert_eq!(
            sdk_trust_tier_to_core_representation(TrustTier::T1),
            CoreTrustTier::Strict
        );
        assert_eq!(
            sdk_trust_tier_to_core_representation(TrustTier::T2),
            CoreTrustTier::Managed
        );
        assert_eq!(
            sdk_trust_tier_to_core_representation(TrustTier::T3),
            CoreTrustTier::Expedient
        );
        assert_eq!(
            sdk_trust_tier_to_core_representation(TrustTier::T4),
            CoreTrustTier::ObserverOnly
        );

        for tier in [TrustTier::T1, TrustTier::T2, TrustTier::T3] {
            assert_eq!(
                core_trust_tier_to_sdk_representation(sdk_trust_tier_to_core_representation(tier)),
                tier
            );
            assert!(
                core_trust_tier_to_sdk_production(sdk_trust_tier_to_core_representation(tier))
                    .is_ok()
            );
            assert!(project_production_rail_policy(
                tier,
                CoreVerificationClass::LightClient,
                Network::Mainnet,
                Chain::BITCOIN,
            )
            .is_ok());
        }
        assert_eq!(
            core_trust_tier_to_sdk_representation(CoreTrustTier::ObserverOnly),
            TrustTier::T4
        );
        assert!(core_trust_tier_to_sdk_production(CoreTrustTier::ObserverOnly).is_err());
        assert!(project_production_rail_policy(
            TrustTier::T4,
            CoreVerificationClass::LightClient,
            Network::Mainnet,
            Chain::BITCOIN,
        )
        .is_err());
    }

    #[test]
    fn core_verification_class_uses_exact_snake_case_values() {
        let values = [
            (CoreVerificationClass::LightClient, "light_client"),
            (CoreVerificationClass::ExternalQuorum, "external_quorum"),
            (
                CoreVerificationClass::AppDefinedMultiVerifier,
                "app_defined_multi_verifier",
            ),
            (CoreVerificationClass::SharedPos, "shared_pos"),
            (
                CoreVerificationClass::NativeObservation,
                "native_observation",
            ),
            (CoreVerificationClass::ZkVerified, "zk_verified"),
        ];

        for (value, expected) in values {
            assert_eq!(
                serde_json::to_string(&value).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<CoreVerificationClass>(&format!("\"{expected}\"")).unwrap(),
                value
            );
        }
    }

    #[test]
    fn production_projection_enforces_core_strict_light_client_invariant() {
        assert!(validate_core_trust_tier_policy(
            CoreTrustTier::Strict,
            CoreVerificationClass::ExternalQuorum,
        )
        .is_err());

        let projection = project_production_rail_policy(
            TrustTier::T1,
            CoreVerificationClass::LightClient,
            Network::Mainnet,
            Chain::BITCOIN,
        )
        .unwrap();
        assert_eq!(projection.trust_tier, CoreTrustTier::Strict);
        assert_eq!(
            projection.verification_class,
            CoreVerificationClass::LightClient
        );
    }

    #[test]
    fn supported_chains_map_without_family_collapsing() {
        let supported = [
            (
                Chain::BITCOIN,
                CoreChain::Bitcoin,
                CoreChainFamily::BitcoinUtxo,
            ),
            (
                Chain::STACKS,
                CoreChain::Stacks,
                CoreChainFamily::BitcoinUtxo,
            ),
            (
                Chain::LIQUID,
                CoreChain::Liquid,
                CoreChainFamily::BitcoinUtxo,
            ),
            (
                Chain::LIGHTNING,
                CoreChain::Lightning,
                CoreChainFamily::BitcoinUtxo,
            ),
            (
                Chain::BABYLON,
                CoreChain::Babylon,
                CoreChainFamily::BitcoinUtxo,
            ),
            (Chain::BOB, CoreChain::Bob, CoreChainFamily::Evm),
            (Chain::MEZO, CoreChain::Mezo, CoreChainFamily::Evm),
            (Chain::CITREA, CoreChain::Citrea, CoreChainFamily::Evm),
            (Chain::BOTANIX, CoreChain::Botanix, CoreChainFamily::Evm),
            (Chain::ETHEREUM, CoreChain::Ethereum, CoreChainFamily::Evm),
            (Chain::BASE, CoreChain::Base, CoreChainFamily::Evm),
            (Chain::ARBITRUM, CoreChain::Arbitrum, CoreChainFamily::Evm),
            (Chain::OPTIMISM, CoreChain::Optimism, CoreChainFamily::Evm),
            (Chain::POLYGON, CoreChain::Polygon, CoreChainFamily::Evm),
            (Chain::SOLANA, CoreChain::Solana, CoreChainFamily::SolanaSvm),
            (Chain::APTOS, CoreChain::Aptos, CoreChainFamily::Move),
            (Chain::SUI, CoreChain::Sui, CoreChainFamily::Move),
        ];

        for (sdk_chain, core_chain, family) in supported {
            assert_eq!(sdk_chain_to_core(sdk_chain).unwrap(), core_chain);
            assert_eq!(core_chain.family(), family);
            let projection = project_production_rail_policy(
                TrustTier::T1,
                CoreVerificationClass::LightClient,
                Network::Mainnet,
                sdk_chain,
            )
            .unwrap();
            assert_eq!(projection.chain, core_chain);
            assert_eq!(projection.family, family);
        }

        for unsupported in [Chain::LINEA, Chain::COSMOS, Chain::BaseSepolia] {
            assert!(sdk_chain_to_core(unsupported).is_err());
            assert!(project_production_rail_policy(
                TrustTier::T1,
                CoreVerificationClass::LightClient,
                Network::Mainnet,
                unsupported,
            )
            .is_err());
        }
    }

    #[test]
    fn production_projection_rejects_testnet_and_devnet() {
        assert!(validate_production_network_context(Network::Mainnet).is_ok());
        assert!(validate_production_network_context(Network::Testnet).is_err());
        assert!(validate_production_network_context(Network::Devnet).is_err());
        assert!(project_production_rail_policy(
            TrustTier::T1,
            CoreVerificationClass::LightClient,
            Network::Testnet,
            Chain::BITCOIN,
        )
        .is_err());
        assert!(project_production_rail_policy(
            TrustTier::T1,
            CoreVerificationClass::LightClient,
            Network::Devnet,
            Chain::BITCOIN,
        )
        .is_err());
    }

    #[test]
    fn bip110_defaults_and_shape_use_exact_core_wire_contract() {
        let limits = CoreBip110Limits::default();
        assert_eq!(
            limits,
            CoreBip110Limits {
                max_pushdata_bytes: 256,
                max_op_return_bytes: 83,
                max_script_pubkey_bytes: 34,
                max_witness_element_bytes: 256,
            }
        );
        assert_eq!(
            serde_json::to_string(&limits).unwrap(),
            r#"{"max_pushdata_bytes":256,"max_op_return_bytes":83,"max_script_pubkey_bytes":34,"max_witness_element_bytes":256}"#
        );
        assert_eq!(
            serde_json::from_str::<CoreBip110Limits>(&serde_json::to_string(&limits).unwrap())
                .unwrap(),
            limits
        );

        let shape = CoreBip110TransactionShape::new(vec![1], vec![2], vec![3], vec![4]);
        assert_eq!(shape.pushdata_sizes_bytes, vec![1]);
        assert_eq!(shape.op_return_script_pubkey_sizes_bytes, vec![2]);
        assert_eq!(shape.non_op_return_script_pubkey_sizes_bytes, vec![3]);
        assert_eq!(shape.witness_element_sizes_bytes, vec![4]);
        assert_eq!(
            serde_json::to_string(&shape).unwrap(),
            r#"{"pushdata_sizes_bytes":[1],"op_return_script_pubkey_sizes_bytes":[2],"non_op_return_script_pubkey_sizes_bytes":[3],"witness_element_sizes_bytes":[4]}"#
        );
        assert_eq!(
            serde_json::from_str::<CoreBip110TransactionShape>(
                &serde_json::to_string(&shape).unwrap()
            )
            .unwrap(),
            shape
        );
    }

    #[test]
    fn bip110_provenance_fixture_matches_core_wire_contract() {
        #[derive(Debug, Deserialize)]
        struct Provenance {
            repository: String,
            commit: String,
            pull_request: u64,
        }

        #[derive(Debug, Deserialize)]
        struct Fixture {
            provenance: Provenance,
            limits: CoreBip110Limits,
            transaction_shape: CoreBip110TransactionShape,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/core_bip110_pr184.json"
        )))
        .unwrap();

        assert_eq!(fixture.provenance.repository, "Conxian/lib-conxian-core");
        assert_eq!(
            fixture.provenance.commit,
            "1699cf3b04ee0755756f5e8c38ec37388c89efbd"
        );
        assert_eq!(fixture.provenance.pull_request, 184);
        assert_eq!(fixture.limits, CoreBip110Limits::canonical());
        assert_eq!(
            fixture.transaction_shape,
            CoreBip110TransactionShape::new(
                vec![32, 256],
                vec![80, 83],
                vec![22, 34],
                vec![64, 256],
            )
        );
    }

    #[test]
    fn signed_envelope_identity_and_serialization_are_deterministic() {
        let descriptor = CoreSignedEnvelopeDescriptor {
            event_id: " evt-123 ".to_string(),
            sequence: 42,
            publisher: " gateway-a ".to_string(),
            payload_hash: "hash".to_string(),
            commitments: vec!["c1".to_string(), "c2".to_string()],
        };

        assert_eq!(descriptor.idempotency_key(), "gateway-a:evt-123:42");
        assert_eq!(
            descriptor.deterministic_serialized_json().unwrap(),
            r#"{"event_id":" evt-123 ","sequence":42,"publisher":" gateway-a ","payload_hash":"hash","commitments":["c1","c2"]}"#
        );
        assert_eq!(
            descriptor.deterministic_serialized_bytes().unwrap(),
            descriptor
                .deterministic_serialized_json()
                .unwrap()
                .as_bytes()
        );
    }
}
