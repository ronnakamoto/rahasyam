use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use super::{DynAdapter, DynProvingSystem, ProofSystemId, ProvingError, ProvingSystem};

pub struct ProofSystemRegistry {
    systems: HashMap<ProofSystemId, Arc<dyn DynProvingSystem>>,
    active: ProofSystemId,
}

impl Default for ProofSystemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofSystemRegistry {
    pub fn new() -> Self {
        Self {
            systems: HashMap::new(),
            active: ProofSystemId::ReservedZero,
        }
    }

    pub fn register<P: ProvingSystem>(&mut self) -> Result<(), ProvingError> {
        let id = P::id();
        if self.systems.contains_key(&id) {
            return Err(ProvingError::RegistryError(format!(
                "Proof system {id} already registered"
            )));
        }
        let adapter = Arc::new(DynAdapter::<P>::new());
        self.systems.insert(id, adapter);
        if self.active == ProofSystemId::ReservedZero {
            self.active = id;
        }
        Ok(())
    }

    pub fn get(&self, id: ProofSystemId) -> Option<Arc<dyn DynProvingSystem>> {
        self.systems.get(&id).cloned()
    }

    pub fn active(&self) -> Option<Arc<dyn DynProvingSystem>> {
        self.systems.get(&self.active).cloned()
    }

    pub fn active_id(&self) -> ProofSystemId {
        self.active
    }

    pub fn set_active(&mut self, id: ProofSystemId) -> Result<(), ProvingError> {
        if !self.systems.contains_key(&id) {
            return Err(ProvingError::KeyNotFound(id));
        }
        self.active = id;
        Ok(())
    }

    pub fn is_registered(&self, id: ProofSystemId) -> bool {
        self.systems.contains_key(&id)
    }

    pub fn registered_ids(&self) -> Vec<ProofSystemId> {
        self.systems.keys().copied().collect()
    }
}

pub type SharedRegistry = Arc<RwLock<ProofSystemRegistry>>;

#[cfg(test)]
mod tests {
    use super::*;

    use serde::{Deserialize, Serialize};
    use alloy::primitives::Bytes;
    use ark_serialize::SerializationError;

    use crate::nf_client_proof::{PrivateInputs, Proof, ProvingEngine, PublicInputs};
    use crate::shared_entities::DepositData;
    use crate::shared_entities::OnChainTransaction;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct DummyProof {
        data: Vec<u8>,
    }

    impl Proof for DummyProof {
        fn compress_proof(&self) -> Result<Bytes, SerializationError> {
            Ok(Bytes::from(self.data.clone()))
        }

        fn from_compressed(compressed: Bytes) -> Result<Self, SerializationError> {
            Ok(DummyProof {
                data: compressed.to_vec(),
            })
        }
    }

    #[derive(Debug)]
    struct DummyEngine;

    impl ProvingEngine<DummyProof> for DummyEngine {
        type Error = std::io::Error;

        fn prove(
            _private_inputs: &mut PrivateInputs,
            _public_inputs: &mut PublicInputs,
        ) -> Result<DummyProof, Self::Error> {
            Ok(DummyProof {
                data: vec![1, 2, 3],
            })
        }

        fn verify(
            _proof: &DummyProof,
            _public_inputs: &PublicInputs,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[derive(Debug)]
    struct DummyRollupEngine;

    impl crate::proving::RecursiveProvingEngine<DummyProof> for DummyRollupEngine {
        type Error = std::io::Error;
        type ProofOutput = DummyProof;

        fn setup() -> Result<Self, Self::Error> {
            Ok(DummyRollupEngine)
        }

        fn prove_block(
            &self,
            _deposits: Vec<DepositData>,
            _client_txs: Vec<OnChainTransaction>,
        ) -> Result<Self::ProofOutput, Self::Error> {
            Ok(DummyProof {
                data: vec![4, 5, 6],
            })
        }

        fn verify(&self, _proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct DummyVerifyingKey;

    struct DummyProvingSystem;

    impl ProvingSystem for DummyProvingSystem {
        type ClientProof = DummyProof;
        type ClientEngine = DummyEngine;
        type RollupEngine = DummyRollupEngine;
        type VerifyingKey = DummyVerifyingKey;

        fn id() -> ProofSystemId {
            ProofSystemId::PlonkV1
        }

        fn name() -> &'static str {
            "dummy-v1"
        }

        fn verifying_key() -> &'static Self::VerifyingKey {
            static VK: DummyVerifyingKey = DummyVerifyingKey;
            &VK
        }

        fn onchain_verifier() -> alloy::primitives::Address {
            alloy::primitives::Address::ZERO
        }
    }

    struct DummyProvingSystem2;

    impl ProvingSystem for DummyProvingSystem2 {
        type ClientProof = DummyProof;
        type ClientEngine = DummyEngine;
        type RollupEngine = DummyRollupEngine;
        type VerifyingKey = DummyVerifyingKey;

        fn id() -> ProofSystemId {
            ProofSystemId::NovaV1
        }

        fn name() -> &'static str {
            "dummy-v2"
        }

        fn verifying_key() -> &'static Self::VerifyingKey {
            static VK: DummyVerifyingKey = DummyVerifyingKey;
            &VK
        }

        fn onchain_verifier() -> alloy::primitives::Address {
            alloy::primitives::Address::ZERO
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();

        assert!(registry.is_registered(ProofSystemId::PlonkV1));
        let system = registry.get(ProofSystemId::PlonkV1);
        assert!(system.is_some());
        assert_eq!(system.unwrap().id(), ProofSystemId::PlonkV1);
    }

    #[test]
    fn test_register_duplicate_fails() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();
        let result = registry.register::<DummyProvingSystem>();
        assert!(result.is_err());
    }

    #[test]
    fn test_active_defaults_to_first_registered() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();
        assert_eq!(registry.active_id(), ProofSystemId::PlonkV1);
        assert!(registry.active().is_some());
    }

    #[test]
    fn test_set_active() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();
        registry.register::<DummyProvingSystem2>().unwrap();

        registry.set_active(ProofSystemId::NovaV1).unwrap();
        assert_eq!(registry.active_id(), ProofSystemId::NovaV1);
        assert_eq!(registry.active().unwrap().id(), ProofSystemId::NovaV1);
    }

    #[test]
    fn test_set_active_unknown_fails() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();

        let result = registry.set_active(ProofSystemId::NovaV1);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_unknown_id_returns_none() {
        let registry = ProofSystemRegistry::new();
        assert!(registry.get(ProofSystemId::PlonkV1).is_none());
    }

    #[test]
    fn test_registered_ids() {
        let mut registry = ProofSystemRegistry::new();
        registry.register::<DummyProvingSystem>().unwrap();
        registry.register::<DummyProvingSystem2>().unwrap();

        let ids = registry.registered_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&ProofSystemId::PlonkV1));
        assert!(ids.contains(&ProofSystemId::NovaV1));
    }
}
