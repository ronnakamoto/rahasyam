pub mod client_engine;
pub mod proof;
#[cfg(test)]
mod tests;
pub mod witness;

pub use client_engine::UltraHonkClientEngine;
pub use proof::UltraHonkProof;

use alloy::primitives::Address;

use crate::proving::nova_v1::{
    proof::{NovaClientProof, NovaProof},
    rollup_engine::NovaRollupEngine,
};
use crate::proving::{ProofSystemId, ProvingError, ProvingSystem, RecursiveProvingEngine};
use crate::shared_entities::{DepositData, OnChainTransaction};

pub struct UltraHonkV1System;

impl ProvingSystem for UltraHonkV1System {
    type ClientProof = UltraHonkProof;
    type ClientEngine = UltraHonkClientEngine;
    type RollupEngine = NovaRollupEngine;
    type VerifyingKey = ();

    fn id() -> ProofSystemId {
        ProofSystemId::UltraHonkV1
    }

    fn name() -> &'static str {
        "ultra-honk-v1"
    }

    fn verifying_key() -> &'static Self::VerifyingKey {
        static VK: () = ();
        &VK
    }

    fn onchain_verifier() -> Address {
        Address::ZERO
    }
}

impl RecursiveProvingEngine<UltraHonkProof> for NovaRollupEngine {
    type Error = ProvingError;
    type ProofOutput = NovaProof;

    fn setup() -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <NovaRollupEngine as RecursiveProvingEngine<NovaClientProof>>::setup()
    }

    fn prove_block(
        &self,
        deposits: Vec<DepositData>,
        client_txs: Vec<OnChainTransaction>,
    ) -> Result<Self::ProofOutput, Self::Error> {
        <NovaRollupEngine as RecursiveProvingEngine<NovaClientProof>>::prove_block(
            self, deposits, client_txs,
        )
    }

    fn verify(&self, proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
        <NovaRollupEngine as RecursiveProvingEngine<NovaClientProof>>::verify(self, proof)
    }
}
