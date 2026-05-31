pub mod plonk_v1;
pub mod registry;

pub use registry::{ProofSystemRegistry, SharedRegistry};

use serde::{Deserialize, Serialize};
use std::fmt;

use alloy::primitives::Bytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};

use crate::nf_client_proof::{PrivateInputs, Proof, ProvingEngine, PublicInputs};
use crate::shared_entities::DepositData;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, Default)]
#[repr(u8)]
pub enum ProofSystemId {
    #[default]
    ReservedZero = 0,
    PlonkV1 = 1,
    NovaV1 = 2,
    ReservedFF = 0xFF,
}

impl fmt::Display for ProofSystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofSystemId::PlonkV1 => write!(f, "plonk-v1"),
            ProofSystemId::NovaV1 => write!(f, "nova-v1"),
            ProofSystemId::ReservedZero => write!(f, "reserved-0"),
            ProofSystemId::ReservedFF => write!(f, "reserved-255"),
        }
    }
}

impl ProofSystemId {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(ProofSystemId::ReservedZero),
            1 => Some(ProofSystemId::PlonkV1),
            2 => Some(ProofSystemId::NovaV1),
            0xFF => Some(ProofSystemId::ReservedFF),
            _ => None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "plonk-v1" => Some(ProofSystemId::PlonkV1),
            "nova-v1" => Some(ProofSystemId::NovaV1),
            _ => None,
        }
    }
}

impl CanonicalSerialize for ProofSystemId {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (*self as u8).serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        1
    }
}

impl CanonicalDeserialize for ProofSystemId {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let val = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        Self::from_u8(val).ok_or(ark_serialize::SerializationError::InvalidData)
    }
}

impl Valid for ProofSystemId {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            ProofSystemId::ReservedZero
            | ProofSystemId::PlonkV1
            | ProofSystemId::NovaV1
            | ProofSystemId::ReservedFF => Ok(()),
        }
    }
}

pub trait ProvingSystem: Send + Sync + 'static {
    type ClientProof: Proof;
    type ClientEngine: ProvingEngine<Self::ClientProof>;
    type RollupEngine: RecursiveProvingEngine<Self::ClientProof>;
    type VerifyingKey: Send + Sync + 'static;

    fn id() -> ProofSystemId;
    fn name() -> &'static str;
    fn verifying_key() -> &'static Self::VerifyingKey;
    fn onchain_verifier() -> alloy::primitives::Address;
}

pub trait RecursiveProvingEngine<P: Proof>: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync;
    type ProofOutput: Proof + Send + Sync;

    fn setup() -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn prove_block(
        &self,
        deposits: Vec<DepositData>,
        client_txs: Vec<crate::shared_entities::OnChainTransaction>,
    ) -> Result<Self::ProofOutput, Self::Error>;

    fn verify(&self, proof: &Self::ProofOutput) -> Result<bool, Self::Error>;
}

pub trait DynProvingSystem: Send + Sync + 'static {
    fn id(&self) -> ProofSystemId;

    fn prove_block(
        &self,
        deposits: Vec<DepositData>,
        client_txs: Vec<crate::shared_entities::OnChainTransaction>,
    ) -> Result<Vec<u8>, ProvingError>;

    fn verify_client_proof(&self, proof: Bytes, pi: &PublicInputs) -> Result<bool, ProvingError>;

    fn create_deposit_proof(
        &self,
        data: [DepositData; 4],
        pi: PublicInputs,
    ) -> Result<Bytes, ProvingError>;
}

pub struct DynAdapter<P: ProvingSystem> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: ProvingSystem> Default for DynAdapter<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ProvingSystem> DynAdapter<P> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: ProvingSystem> Clone for DynAdapter<P> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<P: ProvingSystem> DynProvingSystem for DynAdapter<P> {
    fn id(&self) -> ProofSystemId {
        P::id()
    }

    fn prove_block(
        &self,
        deposits: Vec<DepositData>,
        client_txs: Vec<crate::shared_entities::OnChainTransaction>,
    ) -> Result<Vec<u8>, ProvingError> {
        let engine = P::RollupEngine::setup()
            .map_err(|e| ProvingError::ProvingFailed(e.to_string()))?;
        let proof = engine
            .prove_block(deposits, client_txs)
            .map_err(|e| ProvingError::ProvingFailed(e.to_string()))?;
        let mut bytes = Vec::new();
        let id_byte = (P::id() as u8).to_le_bytes();
        bytes.extend_from_slice(&id_byte);
        let proof_bytes = proof.compress_proof()
            .map_err(|e| ProvingError::SerializationError(e.to_string()))?;
        bytes.extend_from_slice(&proof_bytes);
        Ok(bytes)
    }

    fn verify_client_proof(&self, proof: Bytes, pi: &PublicInputs) -> Result<bool, ProvingError> {
        let client_proof = P::ClientProof::from_compressed(proof)
            .map_err(|e| ProvingError::SerializationError(e.to_string()))?;
        P::ClientEngine::verify(&client_proof, pi)
            .map_err(|e| ProvingError::VerificationFailed(e.to_string()))
    }

    fn create_deposit_proof(
        &self,
        data: [DepositData; 4],
        pi: PublicInputs,
    ) -> Result<Bytes, ProvingError> {
        let mut private_inputs = PrivateInputs::for_deposit(&data);
        let mut public_inputs = pi;
        let proof = P::ClientEngine::prove(&mut private_inputs, &mut public_inputs)
            .map_err(|e| ProvingError::ProvingFailed(e.to_string()))?;
        proof
            .compress_proof()
            .map_err(|e| ProvingError::SerializationError(e.to_string()))
    }
}

#[derive(Debug)]
pub enum ProvingError {
    SerializationError(String),
    KeyNotFound(ProofSystemId),
    ProvingFailed(String),
    VerificationFailed(String),
    RegistryError(String),
}

impl fmt::Display for ProvingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvingError::SerializationError(e) => write!(f, "Serialization error: {e}"),
            ProvingError::KeyNotFound(id) => write!(f, "Key not found for proof system: {id}"),
            ProvingError::ProvingFailed(e) => write!(f, "Proving failed: {e}"),
            ProvingError::VerificationFailed(e) => write!(f, "Verification failed: {e}"),
            ProvingError::RegistryError(e) => write!(f, "Registry error: {e}"),
        }
    }
}

impl std::error::Error for ProvingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_system_id_from_u8() {
        assert_eq!(ProofSystemId::from_u8(1), Some(ProofSystemId::PlonkV1));
        assert_eq!(ProofSystemId::from_u8(2), Some(ProofSystemId::NovaV1));
        assert_eq!(ProofSystemId::from_u8(0), Some(ProofSystemId::ReservedZero));
        assert_eq!(ProofSystemId::from_u8(0xFF), Some(ProofSystemId::ReservedFF));
        assert_eq!(ProofSystemId::from_u8(3), None);
    }

    #[test]
    fn test_proof_system_id_from_str() {
        assert_eq!(ProofSystemId::from_str("plonk-v1"), Some(ProofSystemId::PlonkV1));
        assert_eq!(ProofSystemId::from_str("nova-v1"), Some(ProofSystemId::NovaV1));
        assert_eq!(ProofSystemId::from_str("unknown"), None);
    }

    #[test]
    fn test_proof_system_id_serialization_roundtrip() {
        for id in [ProofSystemId::PlonkV1, ProofSystemId::NovaV1] {
            let mut bytes = Vec::new();
            id.serialize_compressed(&mut bytes).unwrap();
            let decoded = ProofSystemId::deserialize_compressed(bytes.as_slice()).unwrap();
            assert_eq!(id, decoded);
        }
    }

    #[test]
    fn test_proof_system_id_display() {
        assert_eq!(format!("{}", ProofSystemId::PlonkV1), "plonk-v1");
        assert_eq!(format!("{}", ProofSystemId::NovaV1), "nova-v1");
    }

    #[test]
    fn test_proof_system_id_repr() {
        assert_eq!(ProofSystemId::PlonkV1 as u8, 1);
        assert_eq!(ProofSystemId::NovaV1 as u8, 2);
        assert_eq!(ProofSystemId::ReservedZero as u8, 0);
        assert_eq!(ProofSystemId::ReservedFF as u8, 0xFF);
    }
}
