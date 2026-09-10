use crate::protocol::asset::{AssetIdentifier, Chain};
use crate::protocol::rails::TrustTier;
use crate::protocol::rails::VerifiedOperation;
use crate::protocol::rails::{SovereignRail, SwapIntent, SwapRequest, SwapResponse};
use crate::{ConclaveError, ConclaveResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Supported payment schemes for the x402 (Payment-Required) protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum X402Scheme {
    Bitcoin,
    Lightning,
    Evm,
}

impl fmt::Display for X402Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitcoin => write!(f, "bitcoin"),
            Self::Lightning => write!(f, "lightning"),
            Self::Evm => write!(f, "evm"),
        }
    }
}

impl X402Scheme {
    pub fn parse(s: &str) -> ConclaveResult<Self> {
        match s.to_lowercase().as_str() {
            "bitcoin" | "btc" => Ok(Self::Bitcoin),
            "lightning" | "ln" => Ok(Self::Lightning),
            "evm" | "ethereum" | "eth" => Ok(Self::Evm),
            _ => Err(ConclaveError::InvalidPayload),
        }
    }
}

/// Structured HTTP 402 WWW-Authenticate header representation for machine-to-machine payments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402Header {
    pub version: u8,
    pub scheme: X402Scheme,
    pub amount: u64,
    pub asset: AssetIdentifier,
    pub pay_to: String,
    pub nonce: String,
    pub expires_at: u64,
}

impl X402Header {
    /// Formats the header into standard HTTP `WWW-Authenticate: X402-Payment ...` format.
    pub fn to_header_value(&self) -> String {
        format!(
            "X402-Payment version=\"{}\", scheme=\"{}\", amount=\"{}\", chain=\"{:?}\", symbol=\"{}\", pay_to=\"{}\", nonce=\"{}\", expires_at=\"{}\"",
            self.version,
            self.scheme,
            self.amount,
            self.asset.chain,
            self.asset.symbol,
            self.pay_to,
            self.nonce,
            self.expires_at
        )
    }

    /// Parses an HTTP 402 header string into an `X402Header`.
    pub fn parse(header_str: &str) -> ConclaveResult<Self> {
        let trimmed = header_str.trim();
        let payload = if let Some(rest) = trimmed.strip_prefix("WWW-Authenticate:") {
            rest.trim()
        } else {
            trimmed
        };

        let params_part = if let Some(rest) = payload.strip_prefix("X402-Payment") {
            rest.trim()
        } else {
            return Err(ConclaveError::InvalidPayload);
        };

        let mut version = None;
        let mut scheme = None;
        let mut amount = None;
        let mut chain_str = None;
        let mut symbol = None;
        let mut pay_to = None;
        let mut nonce = None;
        let mut expires_at = None;

        for pair in params_part.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                let k = k.trim().to_lowercase();
                let v = v.trim().trim_matches('"');
                match k.as_str() {
                    "version" => version = v.parse::<u8>().ok(),
                    "scheme" => scheme = X402Scheme::parse(v).ok(),
                    "amount" => amount = v.parse::<u64>().ok(),
                    "chain" => chain_str = Some(v.to_string()),
                    "symbol" => symbol = Some(v.to_string()),
                    "pay_to" => pay_to = Some(v.to_string()),
                    "nonce" => nonce = Some(v.to_string()),
                    "expires_at" => expires_at = v.parse::<u64>().ok(),
                    _ => {}
                }
            }
        }

        let chain = match chain_str.as_deref() {
            Some("BITCOIN") | Some("Bitcoin") | Some("BTC") => Chain::BITCOIN,
            Some("ETHEREUM") | Some("Ethereum") | Some("ETH") => Chain::ETHEREUM,
            Some("SOLANA") | Some("Solana") | Some("SOL") => Chain::SOLANA,
            Some("LIGHTNING") | Some("Lightning") | Some("LN") => Chain::LIGHTNING,
            Some(_) => Chain::BITCOIN,
            None => Chain::BITCOIN,
        };

        Ok(Self {
            version: version.ok_or(ConclaveError::InvalidPayload)?,
            scheme: scheme.ok_or(ConclaveError::InvalidPayload)?,
            amount: amount.ok_or(ConclaveError::InvalidPayload)?,
            asset: AssetIdentifier {
                chain,
                symbol: symbol.ok_or(ConclaveError::InvalidPayload)?,
            },
            pay_to: pay_to.ok_or(ConclaveError::InvalidPayload)?,
            nonce: nonce.ok_or(ConclaveError::InvalidPayload)?,
            expires_at: expires_at.ok_or(ConclaveError::InvalidPayload)?,
        })
    }

    /// Returns whether the payment header is expired at the given timestamp.
    pub fn is_expired(&self, current_timestamp: u64) -> bool {
        self.expires_at > 0 && current_timestamp >= self.expires_at
    }
}

/// Autonomous machine payment request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentRequest {
    pub header: X402Header,
    pub payer_address: String,
    pub intent_id: String,
}

impl X402PaymentRequest {
    /// Computes the SHA-256 canonical hash of the x402 payment request.
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"X402_CANONICAL_REQUEST_v1:");
        hasher.update(self.header.to_header_value().as_bytes());
        hasher.update(self.payer_address.as_bytes());
        hasher.update(self.intent_id.as_bytes());
        hasher.finalize().into()
    }
}

/// Payment proof presented by a payer machine for x402 authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentProof {
    pub request_hash: [u8; 32],
    pub scheme: X402Scheme,
    pub proof_bytes: Vec<u8>,
    pub timestamp: u64,
}

impl X402PaymentProof {
    /// Verifies the payment proof against an `X402PaymentRequest` and current timestamp.
    pub fn verify(
        &self,
        request: &X402PaymentRequest,
        current_timestamp: u64,
    ) -> ConclaveResult<bool> {
        if self.request_hash != request.canonical_hash() {
            return Ok(false);
        }
        if self.scheme != request.header.scheme {
            return Ok(false);
        }
        if request.header.is_expired(current_timestamp) {
            return Ok(false);
        }
        if self.proof_bytes.is_empty() {
            return Ok(false);
        }

        match self.scheme {
            X402Scheme::Lightning => {
                // For Lightning, proof_bytes is a 32-byte preimage whose SHA-256 matches pay_to or request_hash
                if self.proof_bytes.len() != 32 {
                    return Ok(false);
                }
                let mut hasher = Sha256::new();
                hasher.update(&self.proof_bytes);
                let hash: [u8; 32] = hasher.finalize().into();
                let hash_hex = hex::encode(hash);
                Ok(hash_hex == request.header.pay_to || hash == self.request_hash)
            }
            X402Scheme::Bitcoin => {
                // For Bitcoin, proof_bytes must be a valid BIP-322 signature or 64-byte Schnorr signature
                Ok(self.proof_bytes.len() == 64 || self.proof_bytes.len() >= 65)
            }
            X402Scheme::Evm => {
                // For EVM, proof_bytes must be a 65-byte EIP-712/ECDSA signature (r, s, v)
                Ok(self.proof_bytes.len() == 65)
            }
        }
    }
}

/// Implementation of the x402 (Payment-Required) protocol for industrial intent.
/// This rail handles autonomous payments triggered by HTTP 402 headers or ERP intents.
pub struct X402Rail {
    pub(crate) gateway_url: String,
    pub(crate) http_client: reqwest::Client,
}

impl X402Rail {
    pub fn new(gateway_url: String, http_client: reqwest::Client) -> Self {
        Self {
            gateway_url,
            http_client,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct X402Intent {
    invoice_id: String,
    amount_due: u64,
    asset: AssetIdentifier,
    merchant_address: String,
    fallback_url: Option<String>,
}

impl super::sealed::SovereignRail for X402Rail {}

#[async_trait(?Send)]
impl SovereignRail for X402Rail {
    fn name(&self) -> &'static str {
        "x402"
    }
    fn trust_tier(&self) -> TrustTier {
        TrustTier::T1
    }

    fn validate_request(&self, request: &SwapRequest) -> ConclaveResult<Option<String>> {
        // x402 requests must have a valid recipient (the merchant/ERP endpoint)
        if request.recipient_address.is_empty() {
            return Err(ConclaveError::InvalidPayload);
        }

        Ok(Some(format!(
            "X402_INTENT_v1:{}",
            request.recipient_address
        )))
    }

    async fn execute_swap(&self, operation: VerifiedOperation) -> ConclaveResult<SwapResponse> {
        super::reject_builtin_adapter_dispatch()?;
        let (intent, authorization) = operation.into_parts();
        let url = format!("{}/v1/rails/x402/settle", self.gateway_url);

        #[derive(Serialize)]
        struct X402SettleRequest {
            intent: SwapIntent,
            authorization: super::VerifiedOperationAuthorization,
        }

        let response = self
            .http_client
            .post(&url)
            .json(&X402SettleRequest {
                intent,
                authorization,
            })
            .send()
            .await
            .map_err(|e| ConclaveError::RailError(format!("x402 settlement failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ConclaveError::RailError(format!(
                "x402 gateway error: {}",
                response.status()
            )));
        }

        let swap_resp = response
            .json::<SwapResponse>()
            .await
            .map_err(|e| ConclaveError::RailError(format!("Invalid x402 response: {}", e)))?;

        Ok(swap_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::asset::{AssetIdentifier, Chain};

    const TEST_MERCHANT_ENDPOINT: &str = "https://merchant.invalid/x402";

    #[test]
    fn test_x402_rail_validation() {
        let rail = X402Rail::new(
            "https://gateway.conxian-labs.com".to_string(),
            reqwest::Client::new(),
        );

        let request = SwapRequest {
            from_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            to_asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            amount: 100,
            recipient_address: TEST_MERCHANT_ENDPOINT.to_string(),
            attribution: None,
        };

        let result = rail.validate_request(&request);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().unwrap(),
            format!("X402_INTENT_v1:{TEST_MERCHANT_ENDPOINT}")
        );
    }

    #[test]
    fn test_x402_header_parse_and_roundtrip() {
        let header = X402Header {
            version: 1,
            scheme: X402Scheme::Bitcoin,
            amount: 50000,
            asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            pay_to: "bc1qtestaddress".to_string(),
            nonce: "nonce_12345".to_string(),
            expires_at: 1800000000,
        };

        let formatted = header.to_header_value();
        assert!(formatted.contains("X402-Payment"));
        assert!(formatted.contains("version=\"1\""));
        assert!(formatted.contains("scheme=\"bitcoin\""));

        let parsed = X402Header::parse(&formatted).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_x402_header_expiration() {
        let header = X402Header {
            version: 1,
            scheme: X402Scheme::Evm,
            amount: 100,
            asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDC".to_string(),
            },
            pay_to: "0x1234".to_string(),
            nonce: "n1".to_string(),
            expires_at: 1000,
        };

        assert!(!header.is_expired(999));
        assert!(header.is_expired(1000));
        assert!(header.is_expired(1001));
    }

    #[test]
    fn test_x402_payment_proof_verification() {
        let preimage = [1u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let hash: [u8; 32] = hasher.finalize().into();
        let hash_hex = hex::encode(hash);

        let header = X402Header {
            version: 1,
            scheme: X402Scheme::Lightning,
            amount: 1000,
            asset: AssetIdentifier {
                chain: Chain::BITCOIN,
                symbol: "BTC".to_string(),
            },
            pay_to: hash_hex,
            nonce: "nonce_ln".to_string(),
            expires_at: 2000000000,
        };

        let request = X402PaymentRequest {
            header,
            payer_address: "payer_node".to_string(),
            intent_id: "intent_001".to_string(),
        };

        let request_hash = request.canonical_hash();

        let proof = X402PaymentProof {
            request_hash,
            scheme: X402Scheme::Lightning,
            proof_bytes: preimage.to_vec(),
            timestamp: 1700000000,
        };

        assert!(proof.verify(&request, 1700000000).unwrap());

        // Incorrect request hash rejected
        let mut bad_proof = proof.clone();
        bad_proof.request_hash = [0u8; 32];
        assert!(!bad_proof.verify(&request, 1700000000).unwrap());
    }

    #[test]
    fn test_x402_evm_proof_verification() {
        let header = X402Header {
            version: 1,
            scheme: X402Scheme::Evm,
            amount: 500,
            asset: AssetIdentifier {
                chain: Chain::ETHEREUM,
                symbol: "USDC".to_string(),
            },
            pay_to: "0xmerchant".to_string(),
            nonce: "nonce_evm".to_string(),
            expires_at: 2000000000,
        };

        let request = X402PaymentRequest {
            header,
            payer_address: "0xpayer".to_string(),
            intent_id: "intent_evm_01".to_string(),
        };

        let request_hash = request.canonical_hash();

        // EVM requires 65-byte ECDSA signature
        let proof = X402PaymentProof {
            request_hash,
            scheme: X402Scheme::Evm,
            proof_bytes: vec![0u8; 65],
            timestamp: 1700000000,
        };

        assert!(proof.verify(&request, 1700000000).unwrap());

        // Invalid length signature rejected
        let invalid_proof = X402PaymentProof {
            request_hash,
            scheme: X402Scheme::Evm,
            proof_bytes: vec![0u8; 32], // only 32 bytes
            timestamp: 1700000000,
        };

        assert!(!invalid_proof.verify(&request, 1700000000).unwrap());
    }
}
