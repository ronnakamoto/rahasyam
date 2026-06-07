use alloy::primitives::Bytes;
use ark_serialize::SerializationError;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

use crate::nf_client_proof::Proof;
use crate::proving::ProofSystemId;
use crate::proving::RecursiveProvingEngine;
use crate::shared_entities::DepositData;
use crate::shared_entities::OnChainTransaction;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlonkBlockProof {
    pub proof_bytes: Vec<u8>,
}

impl Proof for PlonkBlockProof {
    fn compress_proof(&self) -> Result<Bytes, SerializationError> {
        bincode::serialize(self)
            .map(Bytes::from)
            .map_err(|_| SerializationError::InvalidData)
    }

    fn from_compressed(compressed: Bytes) -> Result<Self, SerializationError> {
        bincode::deserialize(&compressed).map_err(|_| SerializationError::InvalidData)
    }

    fn system_id() -> ProofSystemId {
        ProofSystemId::PlonkV1
    }
}

#[derive(Debug)]
pub struct PlonkRollupProvingError(String);

impl fmt::Display for PlonkRollupProvingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlonkRollupProvingError: {}", self.0)
    }
}

impl Error for PlonkRollupProvingError {}

pub struct PlonkRollupEngine;

impl RecursiveProvingEngine<crate::plonk_prover::plonk_proof::PlonkProof> for PlonkRollupEngine {
    type Error = PlonkRollupProvingError;
    type ProofOutput = PlonkBlockProof;

    fn setup() -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(PlonkRollupEngine)
    }

    fn prove_block(
        &self,
        _deposits: Vec<DepositData>,
        _client_txs: Vec<OnChainTransaction>,
    ) -> Result<Self::ProofOutput, Self::Error> {
        Err(PlonkRollupProvingError(
            "PlonkRollupEngine::prove_block delegates to existing RollupProver".to_string(),
        ))
    }

    fn verify(&self, _proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl PlonkBlockProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(ProofSystemId::PlonkV1 as u8).to_le_bytes());
        bytes.extend_from_slice(&self.proof_bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.is_empty() {
            return Err(SerializationError::InvalidData);
        }
        let id_byte = bytes[0];
        if id_byte != ProofSystemId::PlonkV1 as u8 {
            return Err(SerializationError::InvalidData);
        }
        bincode::deserialize(&bytes[1..]).map_err(|_| SerializationError::InvalidData)
    }
}
