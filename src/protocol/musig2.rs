use crate::{ConclaveError, ConclaveResult};
use musig2::{
    AggNonce, CompactSignature, KeyAggContext, PartialSignature, PubNonce, SecNonce,
    aggregate_partial_signatures,
};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey};

/// Wrapper for MuSig2 multi-signature orchestration.
pub struct MuSig2Session {
    pub key_agg_ctx: KeyAggContext,
}

impl MuSig2Session {
    pub fn new(pubkeys: &[PublicKey]) -> ConclaveResult<Self> {
        let keys: Vec<PublicKey> = pubkeys.to_vec();
        let key_agg_ctx = KeyAggContext::new(keys)
            .map_err(|e| ConclaveError::CryptoError(format!("MuSig2 KeyAgg failed: {:?}", e)))?;
        Ok(Self { key_agg_ctx })
    }

    pub fn generate_nonce(&self, _secret_key: &SecretKey) -> (SecNonce, PubNonce) {
        let mut rng = rand::rng();
        // Use random bytes to build a nonce seed
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let sec_nonce = SecNonce::build(seed).build();
        let pub_nonce = sec_nonce.public_nonce();
        (sec_nonce, pub_nonce)
    }

    pub fn partial_sign(
        &self,
        sec_nonce: SecNonce,
        pub_nonces: Vec<PubNonce>,
        secret_key: &SecretKey,
        message: [u8; 32],
    ) -> ConclaveResult<PartialSignature> {
        let aggr_nonce = AggNonce::sum(&pub_nonces);

        musig2::sign_partial::<PartialSignature>(
            &self.key_agg_ctx,
            *secret_key,
            sec_nonce,
            &aggr_nonce,
            message,
        )
        .map_err(|e| ConclaveError::CryptoError(format!("MuSig2 signing failed: {:?}", e)))
    }

    pub fn aggregate_signatures(
        &self,
        pub_nonces: Vec<PubNonce>,
        partial_sigs: Vec<PartialSignature>,
        message: [u8; 32],
    ) -> ConclaveResult<Vec<u8>> {
        let aggr_nonce = AggNonce::sum(&pub_nonces);

        let final_sig: CompactSignature =
            aggregate_partial_signatures(&self.key_agg_ctx, &aggr_nonce, partial_sigs, message)
                .map_err(|e| {
                    ConclaveError::CryptoError(format!("MuSig2 aggregation failed: {:?}", e))
                })?;

        Ok(final_sig.serialize().to_vec())
    }
}
