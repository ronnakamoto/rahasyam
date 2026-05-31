pub use crate::plonk_prover::plonk_proof::PlonkProof;
pub use crate::plonk_prover::plonk_proof::PlonkProvingEngine;
pub mod keys;
pub mod rollup_engine;

use alloy::primitives::Address;

use super::{ProofSystemId, ProvingSystem};
use crate::proving::plonk_v1::rollup_engine::PlonkRollupEngine;
use crate::proving::plonk_v1::keys::PlonkVerifyingKey;

pub struct PlonkV1System;

impl ProvingSystem for PlonkV1System {
    type ClientProof = PlonkProof;
    type ClientEngine = PlonkProvingEngine;
    type RollupEngine = PlonkRollupEngine;
    type VerifyingKey = PlonkVerifyingKey;

    fn id() -> ProofSystemId {
        ProofSystemId::PlonkV1
    }

    fn name() -> &'static str {
        "plonk-v1"
    }

    fn verifying_key() -> &'static Self::VerifyingKey {
        static VK: PlonkVerifyingKey = PlonkVerifyingKey;
        &VK
    }

    fn onchain_verifier() -> Address {
        Address::ZERO
    }
}
