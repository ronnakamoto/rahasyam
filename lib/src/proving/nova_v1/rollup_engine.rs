//! Nova Rollup Engine
//!
//! Implements the rollup block proving for Nova-SNARK using Incremental
//! Verifiable Computation (IVC).
//!
//! ## Nova API (v0.71.1)
//!
//! ```ignore
//! // Type aliases
//! type E1 = Bn256EngineKZG;       // BN254 primary curve (with HyperKZG)
//! type E2 = GrumpkinEngine;        // Grumpkin secondary curve (with IPA)
//!
//! // Evaluation engines
//! type EE1 = hyperkzg::EvaluationEngine<E1>;
//! type EE2 = ipa_pc::EvaluationEngine<E2>;
//!
//! // SNARK compressors
//! type S1 = RelaxedR1CSSNARK<E1, EE1>;
//! type S2 = RelaxedR1CSSNARK<E2, EE2>;
//!
//! // Setup
//! let pp = PublicParams::<E1, E2, C>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())?;
//!
//! // IVC folding
//! let mut rs = RecursiveSNARK::<E1, E2, C>::new(&pp, &circuit, &z0)?;
//! for circuit_step in circuits { rs.prove_step(&pp, &circuit_step)?; }
//! rs.verify(&pp, num_steps, &z0)?;
//!
//! // Compression
//! let (pk, vk) = CompressedSNARK::<_, _, _, S1, S2>::setup(&pp)?;
//! let snark = CompressedSNARK::<_, _, _, S1, S2>::prove(&pp, &pk, &rs)?;
//! snark.verify(&vk, num_steps, &z0)?;
//! ```
//!
//! ## References
//!
//! - <https://docs.rs/nova-snark/0.71.1/>
//! - `~/.cargo/registry/.../nova-snark-0.71.1/examples/minroot.rs`

#[cfg(feature = "nova-v1")]
mod nova_integration {
    use std::sync::{Arc, OnceLock};
    use crate::proving::nova_v1::proof::{NovaProof, NovaClientProof};
    use crate::proving::nova_v1::step_circuit::nova_step_circuit::{
        RollupIvcState, RollupStepCircuit,
    };
    use crate::proving::{ProvingError, RecursiveProvingEngine};
    use crate::shared_entities::{DepositData, OnChainTransaction};

    use nova_snark::{
        nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{snark::RelaxedR1CSSNARKTrait, Engine},
    };
    use ff::{Field, PrimeField};

    // ------------------------------------------------------------------
    // Type aliases following the minroot example pattern.
    // ------------------------------------------------------------------

    /// Primary curve engine: BN254 with HyperKZG polynomial commitment
    pub type E1 = Bn256EngineKZG;
    /// Secondary curve engine: Grumpkin with IPA polynomial commitment
    pub type E2 = GrumpkinEngine;
    /// Evaluation engine for primary curve (HyperKZG)
    pub type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    /// Evaluation engine for secondary curve (IPA)
    pub type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    /// SNARK compressor for primary circuit
    pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
    /// SNARK compressor for secondary circuit
    pub type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

    /// Scalar field of the primary engine (halo2curves::bn256::Scalar, implements ff::PrimeField)
    pub type F1 = <E1 as Engine>::Scalar;

    /// Convenience type alias for the rollup step circuit.
    pub type RollupCircuit = RollupStepCircuit<F1>;

    /// Compressed SNARK type for rollup blocks.
    pub type RollupCompressedSNARK = CompressedSNARK<E1, E2, RollupCircuit, S1, S2>;

    /// Nova Rollup Engine
    ///
    /// Generates Nova IVC proofs for rollup blocks.
    ///
    /// **Thread safety:** The `PublicParams` and SNARK keys are cached in `OnceLock`
    /// so the expensive `setup()` and loading is paid only once per process.
    pub struct NovaRollupEngine {
        /// Maximum number of IVC steps (transactions) per block.
        max_steps: usize,
    }

    impl Default for NovaRollupEngine {
        fn default() -> Self {
            Self::new()
        }
    }

    // Global caches for the keys so they are only loaded/generated once
    static PUBLIC_PARAMS: OnceLock<Arc<PublicParams<E1, E2, RollupCircuit>>> = OnceLock::new();
    static SNARK_PK: OnceLock<Arc<nova_snark::nova::ProverKey<E1, E2, RollupCircuit, S1, S2>>> = OnceLock::new();
    static SNARK_VK: OnceLock<Arc<nova_snark::nova::VerifierKey<E1, E2, RollupCircuit, S1, S2>>> = OnceLock::new();

    impl NovaRollupEngine {
        pub fn new() -> Self {
            Self { max_steps: 1000 }
        }

        #[allow(dead_code)]
        pub fn with_max_steps(max_steps: usize) -> Self {
            Self { max_steps }
        }

        #[allow(dead_code)]
        pub fn max_steps(&self) -> usize {
            self.max_steps
        }

        /// Build the IVC step circuits for a given list of transactions.
        ///
        /// **TODO (follow-up to 1.1):** wire actual Merkle inclusion paths
        /// from the proposer's commitment tree and IMT non-inclusion
        /// witnesses from the nullifier tree into each step circuit via
        /// [`RollupCircuit::new_real`]. The witnesses must be computed
        /// off-chain by the proposer at block-construction time and
        /// passed through the proving pipeline.
        ///
        /// Until that plumbing lands, every step is emitted as a padding
        /// step: the IVC chain still folds correctly (Nova's soundness is
        /// preserved), but the chain does **not** advance the
        /// `commitments_root` / `nullifiers_root` state. This keeps the
        /// rollup engine structurally functional for tests and
        /// benchmarking while signalling clearly that production block
        /// proving requires the missing plumbing.
        fn build_circuits(
            _deposits: &[DepositData],
            client_txs: &[OnChainTransaction],
        ) -> Vec<RollupCircuit> {
            client_txs
                .iter()
                .map(|_tx| RollupCircuit::padding())
                .collect()
        }

        /// Starting state vector for the IVC sequence.
        fn initial_z0() -> Vec<F1> {
            vec![F1::ZERO, F1::ZERO, F1::ZERO, F1::ZERO]
        }

        /// Extract the IVC state from the `z` output vector.
        fn extract_ivc_state(z_out: &[F1]) -> RollupIvcState {
            // The z vector contains field elements; convert back to bytes.
            fn f1_to_bytes(f: F1) -> Vec<u8> {
                let mut bytes = vec![0u8; 32];
                let repr = f.to_repr();
                let ref_bytes = repr.as_ref();
                let len = ref_bytes.len().min(32);
                bytes[..len].copy_from_slice(&ref_bytes[..len]);
                bytes
            }

                RollupIvcState {
                commitments_root: f1_to_bytes(z_out[0]),
                nullifiers_root: f1_to_bytes(z_out[1]),
                historic_root_root: f1_to_bytes(z_out[2]),
                transaction_count: {
                    let repr = z_out[3].to_repr();
                    let bytes = repr.as_ref();
                    let mut arr = [0u8; 8];
                    let len = bytes.len().min(8);
                    arr[..len].copy_from_slice(&bytes[..len]);
                    u64::from_le_bytes(arr)
                },
            }
        }

        /// Run the IVC folding loop over a sequence of pre-built `RollupCircuit`
        /// steps and compress the output.
        pub fn prove_circuits(
            &self,
            circuits: Vec<RollupCircuit>,
        ) -> Result<NovaProof, ProvingError> {
            if circuits.is_empty() {
                // Return an empty proof for empty blocks
                return Ok(NovaProof {
                    snark_proof: vec![],
                    commitments_root: vec![0u8; 32],
                    nullifiers_root: vec![0u8; 32],
                    historic_root_root: vec![0u8; 32],
                    transaction_count: 0,
                });
            }

            // Enforce the per-block IVC step ceiling so a malformed batch
            // cannot trigger an unbounded folding loop. PublicParams are
            // sized for the configured `max_steps` and proving beyond that
            // is rejected eagerly with a clear error.
            if circuits.len() > self.max_steps {
                return Err(ProvingError::ProvingFailed(format!(
                    "circuits len ({}) exceeds configured max_steps ({})",
                    circuits.len(),
                    self.max_steps,
                )));
            }

            // Ensure setup has run
            let _ = Self::setup()?;

            // ------------------------------------------------------------------
            // 1. Get cached public parameters
            // ------------------------------------------------------------------
            log::info!("[nova-v1] Using cached PublicParams...");
            let pp = PUBLIC_PARAMS.get().expect("Public params not initialized");

            let num_steps = circuits.len();
            let z0 = Self::initial_z0();

            // ------------------------------------------------------------------
            // 2. IVC folding.
            // ------------------------------------------------------------------
            let first_circuit = circuits.first().unwrap();

            let mut rs = RecursiveSNARK::<E1, E2, RollupCircuit>::new(&**pp, first_circuit, &z0)
                .map_err(|e| ProvingError::ProvingFailed(format!("RecursiveSNARK::new: {e}")))?;

            for (i, circuit) in circuits.iter().enumerate() {
                rs.prove_step(&**pp, circuit).map_err(|e| {
                    ProvingError::ProvingFailed(format!("prove_step[{i}]: {e}"))
                })?;
            }

            // Extract final IVC state from the output z vector.
            let z_out = rs
                .verify(&**pp, num_steps, &z0)
                .map_err(|e| {
                    ProvingError::VerificationFailed(format!("IVC verify (state extract): {e}"))
                })?;
            let ivc_state = Self::extract_ivc_state(&z_out);

            // ------------------------------------------------------------------
            // 3. Compress with Spartan SNARK.
            // ------------------------------------------------------------------
            log::info!("[nova-v1] compressing {} steps with Spartan…", num_steps);
            let pk = SNARK_PK.get().expect("SNARK PK not initialized");

            let compressed = RollupCompressedSNARK::prove(&**pp, &**pk, &rs)
                .map_err(|e| ProvingError::ProvingFailed(format!("CompressedSNARK::prove: {e}")))?;

            // ------------------------------------------------------------------
            // 4. Serialise to `NovaProof`.
            // ------------------------------------------------------------------
            // Use bincode + serde for the compressed SNARK (nova-snark io feature).
            let snark_bytes = bincode::serialize(&compressed)
                .map_err(|e| ProvingError::SerializationError(format!("bincode serialize: {e}")))?;

            let proof = NovaProof {
                snark_proof: snark_bytes,
                commitments_root: ivc_state.commitments_root,
                nullifiers_root: ivc_state.nullifiers_root,
                historic_root_root: ivc_state.historic_root_root,
                transaction_count: ivc_state.transaction_count as usize,
            };

            log::info!(
                "[nova-v1] prove_block complete: {} txs, proof size {} bytes",
                num_steps,
                proof.snark_proof.len()
            );
            Ok(proof)
        }
    }

    impl RecursiveProvingEngine<NovaClientProof> for NovaRollupEngine {
        type Error = ProvingError;
        type ProofOutput = NovaProof;

        fn setup() -> Result<Self, Self::Error>
        where
            Self: Sized,
        {
            let key_manager = crate::proving::nova_v1::keys::NovaKeyManager::with_default_dir();

            // Initialize global parameters if not already loaded.
            // PublicParams are loaded from disk when available; otherwise
            // generated via the supplied closure and persisted.
            PUBLIC_PARAMS.get_or_init(|| {
                let pp = key_manager
                    .load_or_generate_ivc_pk(|| {
                        let dummy_circuit = RollupCircuit::padding();
                        PublicParams::<E1, E2, RollupCircuit>::setup(
                            &dummy_circuit,
                            &*S1::ck_floor(),
                            &*S2::ck_floor(),
                        )
                        .expect("PublicParams setup failed")
                    })
                    .expect("Failed to load or generate PublicParams");
                Arc::new(pp)
            });

            // Spartan PK/VK are similarly cached on disk so the expensive
            // CompressedSNARK::setup runs at most once per (circuit, version).
            SNARK_PK.get_or_init(|| {
                let pp = PUBLIC_PARAMS.get().unwrap();
                let (pk, vk) = key_manager
                    .load_or_generate_snark_keys::<E1, E2, RollupCircuit, S1, S2>(|| {
                        RollupCompressedSNARK::setup(pp)
                            .expect("Failed to setup CompressedSNARK")
                    })
                    .expect("Failed to load or generate CompressedSNARK keys");
                let _ = SNARK_VK.set(Arc::new(vk));
                Arc::new(pk)
            });

            Ok(Self::new())
        }

        /// Prove a rollup block using Nova IVC and compress it with Spartan.
        fn prove_block(
            &self,
            deposits: Vec<DepositData>,
            client_txs: Vec<OnChainTransaction>,
        ) -> Result<Self::ProofOutput, Self::Error> {
            if client_txs.is_empty() && deposits.is_empty() {
                // Return an empty proof for empty blocks
                return Ok(NovaProof {
                    snark_proof: vec![],
                    commitments_root: vec![0u8; 32],
                    nullifiers_root: vec![0u8; 32],
                    historic_root_root: vec![0u8; 32],
                    transaction_count: 0,
                });
            }
            let circuits = Self::build_circuits(&deposits, &client_txs);
            self.prove_circuits(circuits)
        }

        /// Verify a Nova block proof.
        ///
        /// Deserializes the `CompressedSNARK` and calls `verify`.
        fn verify(&self, proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
            // Empty proof for empty block is valid by convention.
            if proof.snark_proof.is_empty() && proof.transaction_count == 0 {
                return Ok(true);
            }

            if proof.snark_proof.is_empty() {
                return Err(ProvingError::VerificationFailed(
                    "Empty snark_proof for non-empty block".into(),
                ));
            }

            // Deserialize the compressed SNARK.
            let compressed: RollupCompressedSNARK = bincode::deserialize(&proof.snark_proof)
                .map_err(|e| {
                    ProvingError::VerificationFailed(format!("CompressedSNARK deserialization: {e}"))
                })?;

            // Reconstruct public params and VK for verification.
            // NOTE: In production this would load VK from disk (NovaKeyManager).
            let vk = SNARK_VK.get().ok_or_else(|| {
                ProvingError::VerificationFailed("SNARK VK not initialized".into())
            })?;

            let z0 = Self::initial_z0();
            let num_steps = proof.transaction_count;

            compressed
                .verify(&vk, num_steps, &z0)
                .map(|_| true)
                .map_err(|e| ProvingError::VerificationFailed(format!("CompressedSNARK::verify: {e}")))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_nova_rollup_engine_setup() {
            let engine = NovaRollupEngine::setup();
            assert!(engine.is_ok());
        }

        #[test]
        fn test_nova_rollup_engine_empty_block() {
            let engine = NovaRollupEngine::new();
            let result = engine.prove_block(Vec::new(), Vec::new());
            assert!(result.is_ok(), "empty block should return default proof");
            let proof = result.unwrap();
            assert_eq!(proof.transaction_count, 0);
            assert!(proof.snark_proof.is_empty());
        }

        #[test]
        fn test_nova_rollup_engine_empty_block_verify() {
            let engine = NovaRollupEngine::new();
            let proof = engine.prove_block(Vec::new(), Vec::new()).unwrap();
            let result = engine.verify(&proof);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }

        #[test]
        fn test_nova_rollup_engine_max_steps_exceeded() {
            let engine = NovaRollupEngine::with_max_steps(2);
            // 3 client_txs exceeds max_steps = 2
            let txs = vec![
                OnChainTransaction::default(),
                OnChainTransaction::default(),
                OnChainTransaction::default(),
            ];
            let result = engine.prove_block(Vec::new(), txs);
            assert!(result.is_err());
        }
    }
}

#[cfg(not(feature = "nova-v1"))]
mod nova_integration {
    use crate::proving::{ProvingError, RecursiveProvingEngine};
    use crate::proving::nova_v1::proof::{NovaProof, NovaClientProof};
    use crate::shared_entities::{DepositData, OnChainTransaction};

    /// Stub implementation when nova-v1 feature is not enabled.
    pub struct NovaRollupEngine;
    
    // Stub types to satisfy the re-export at the bottom of the file
    pub type RollupCircuit = super::step_circuit::RollupStepCircuit;
    pub type F1 = ark_bn254::Fr;

    impl NovaRollupEngine {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for NovaRollupEngine {
        fn default() -> Self {
            Self
        }
    }

    impl RecursiveProvingEngine<NovaClientProof> for NovaRollupEngine {
        type Error = ProvingError;
        type ProofOutput = NovaProof;

        fn setup() -> Result<Self, Self::Error>
        where
            Self: Sized,
        {
            Ok(Self)
        }

        fn prove_block(
            &self,
            _deposits: Vec<DepositData>,
            _client_txs: Vec<OnChainTransaction>,
        ) -> Result<Self::ProofOutput, Self::Error> {
            Err(ProvingError::ProvingFailed(
                "Nova V1 feature not enabled. Build with --features nova-v1".to_string(),
            ))
        }

        fn verify(&self, _proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
            Err(ProvingError::VerificationFailed(
                "Nova V1 feature not enabled".to_string(),
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_nova_rollup_engine_disabled() {
            let engine = NovaRollupEngine::new();
            let result = engine.prove_block(Vec::new(), Vec::new());
            assert!(result.is_err());
        }
    }
}

// Re-export for use in parent module.
pub use nova_integration::{NovaRollupEngine, RollupCircuit, F1};
