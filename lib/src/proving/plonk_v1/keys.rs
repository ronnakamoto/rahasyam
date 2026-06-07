use crate::plonk_prover::get_client_proving_key;

#[derive(Debug, Clone, Copy)]
pub struct PlonkVerifyingKey;

impl PlonkVerifyingKey {
    pub fn get_client_vk() -> &'static jf_plonk::nightfall::ipa_structs::VerifyingKey<
        jf_primitives::pcs::prelude::UnivariateKzgPCS<ark_bn254::Bn254>,
    > {
        &get_client_proving_key().vk
    }
}
