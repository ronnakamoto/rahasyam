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
    use crate::proving::nova_v1::commitment_tree::compute_initial_z0;
    use crate::proving::nova_v1::proof::{NovaClientProof, NovaProof};
    use crate::proving::nova_v1::step_circuit::nova_step_circuit::{
        RollupIvcState, RollupStepCircuit,
    };
    use crate::proving::{ProvingError, RecursiveProvingEngine};
    use crate::shared_entities::{DepositData, OnChainTransaction};
    use std::sync::{Arc, OnceLock};

    use ff::PrimeField;
    use nova_snark::{
        nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{snark::RelaxedR1CSSNARKTrait, Engine},
    };

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

    /// Serialize an `F1` (Nova primary scalar) to 32 little-endian bytes,
    /// matching the encoding used when the prover stamps the IVC output
    /// roots into [`NovaProof`] (see [`NovaRollupEngine::extract_ivc_state`]).
    /// Kept module-private so the verify-side binding and the prove-side
    /// extraction stay in lockstep.
    fn f1_to_bytes(f: F1) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        let repr = f.to_repr();
        let ref_bytes = repr.as_ref();
        let len = ref_bytes.len().min(32);
        bytes[..len].copy_from_slice(&ref_bytes[..len]);
        bytes
    }

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
    static SNARK_PK: OnceLock<Arc<nova_snark::nova::ProverKey<E1, E2, RollupCircuit, S1, S2>>> =
        OnceLock::new();
    static SNARK_VK: OnceLock<Arc<nova_snark::nova::VerifierKey<E1, E2, RollupCircuit, S1, S2>>> =
        OnceLock::new();

    impl NovaRollupEngine {
        /// Default upper bound on the number of IVC steps per block.
        ///
        /// **MUST match the on-chain `MAX_STEPS` constant** in
        /// `blockchain_assets/contracts/proof_verification/nova_v1/NovaRollupVerifier.sol`.
        /// Operators can override this at proposer startup via
        /// `settings.nightfall_proposer.nova_max_steps`.
        pub const DEFAULT_MAX_STEPS: usize = 10_000;

        pub fn new() -> Self {
            Self {
                max_steps: Self::DEFAULT_MAX_STEPS,
            }
        }

        /// Construct a Nova rollup engine with an explicit per-block
        /// step cap. Production code should obtain the value from
        /// `settings.nightfall_proposer.nova_max_steps` so that
        /// off-chain and on-chain limits stay in lockstep.
        pub fn with_max_steps(max_steps: usize) -> Self {
            Self { max_steps }
        }

        #[allow(dead_code)]
        pub fn max_steps(&self) -> usize {
            self.max_steps
        }

        /// Build the IVC step circuits for a given list of transactions.
        ///
        /// This is the **legacy** zero-witness step builder kept for
        /// unit tests and benchmarks. **Production code MUST use**
        /// [`crate::proving::nova_v1::witness::build_rollup_circuits`]
        /// which builds steps with real Merkle inclusion and IMT
        /// non-inclusion witnesses.
        ///
        /// The legacy builder emits padding steps that do not advance
        /// `commitments_root` / `nullifiers_root`; Nova's folding
        /// soundness is preserved (the IVC still verifies), but the
        /// per-step Merkle gadgets accept all-zero witnesses because
        /// the step is gated on `is_padding = true`. This is fine for
        /// IVC setup testing, but it is not a sound proof of a state
        /// transition.
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
        ///
        /// Uses the neptune-Poseidon empty-tree roots so that the first
        /// step's Merkle / IMT witnesses (built against those roots)
        /// satisfy the circuit constraints.
        fn initial_z0() -> Vec<F1> {
            crate::proving::nova_v1::commitment_tree::compute_initial_z0()
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
                nullifier_count: {
                    let repr = z_out[4].to_repr();
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
            log::info!(
                "[nova-v1] z0 = [{:?}, {:?}, {:?}, {:?}]",
                z0[0],
                z0[1],
                z0[2],
                z0[3]
            );

            // ------------------------------------------------------------------
            // 2. IVC folding.
            // ------------------------------------------------------------------
            let first_circuit = circuits.first().unwrap();

            let mut rs = RecursiveSNARK::<E1, E2, RollupCircuit>::new(&**pp, first_circuit, &z0)
                .map_err(|e| ProvingError::ProvingFailed(format!("RecursiveSNARK::new: {e}")))?;

            for (i, circuit) in circuits.iter().enumerate() {
                rs.prove_step(&**pp, circuit)
                    .map_err(|e| ProvingError::ProvingFailed(format!("prove_step[{i}]: {e}")))?;
            }

            // Extract final IVC state from the output z vector.
            let z_out = rs.verify(&**pp, num_steps, &z0).map_err(|e| {
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

        /// Same as [`prove_circuits`] but accepts a custom initial IVC
        /// state `z0`. This is required for blocks that follow prior
        /// blocks with non-zero nullifiers: the Neptune IMT is hydrated
        /// with the prior nullifiers, so `z0[1]` must be the hydrated
        /// root (not the empty-tree root).
        pub fn prove_circuits_with_z0(
            &self,
            circuits: Vec<RollupCircuit>,
            z0: [F1; 5],
        ) -> Result<NovaProof, ProvingError> {
            if circuits.is_empty() {
                return Ok(NovaProof {
                    snark_proof: vec![],
                    commitments_root: vec![0u8; 32],
                    nullifiers_root: vec![0u8; 32],
                    historic_root_root: vec![0u8; 32],
                    transaction_count: 0,
                });
            }
            if circuits.len() > self.max_steps {
                return Err(ProvingError::ProvingFailed(format!(
                    "circuits len ({}) exceeds configured max_steps ({})",
                    circuits.len(),
                    self.max_steps,
                )));
            }
            let _ = Self::setup()?;
            let pp = PUBLIC_PARAMS.get().expect("Public params not initialized");
            let num_steps = circuits.len();
            log::info!(
                "[nova-v1] prove_circuits_with_z0: z0 = [{:?}, {:?}, {:?}, {:?}, {:?}]",
                z0[0],
                z0[1],
                z0[2],
                z0[3],
                z0[4]
            );

            let first_circuit = circuits.first().unwrap();
            let mut rs = RecursiveSNARK::<E1, E2, RollupCircuit>::new(&**pp, first_circuit, &z0)
                .map_err(|e| ProvingError::ProvingFailed(format!("RecursiveSNARK::new: {e}")))?;

            for (i, circuit) in circuits.iter().enumerate() {
                rs.prove_step(&**pp, circuit)
                    .map_err(|e| ProvingError::ProvingFailed(format!("prove_step[{i}]: {e}")))?;
            }

            let z_out = rs.verify(&**pp, num_steps, &z0).map_err(|e| {
                ProvingError::VerificationFailed(format!("IVC verify (state extract): {e}"))
            })?;
            let ivc_state = Self::extract_ivc_state(&z_out);

            log::info!("[nova-v1] compressing {} steps with Spartan…", num_steps);
            let pk = SNARK_PK.get().expect("SNARK PK not initialized");
            let compressed = RollupCompressedSNARK::prove(&**pp, &**pk, &rs)
                .map_err(|e| ProvingError::ProvingFailed(format!("CompressedSNARK::prove: {e}")))?;

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
                "[nova-v1] prove_circuits_with_z0 complete: {} txs, proof size {} bytes",
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
            use nova_snark::frontend::{
                num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem,
            };
            use nova_snark::traits::circuit::StepCircuit;

            let key_manager = crate::proving::nova_v1::keys::NovaKeyManager::with_default_dir();

            // The circuit's arity and constraint count together form the
            // canonical fingerprint for the persisted PublicParams / SNARK
            // keys. Arity catches state-vector changes; constraint count
            // catches gadget changes that keep arity constant (e.g. adding
            // the nullifier insertion witness). Both are checked by the
            // key manager's envelope on load.
            let expected_arity =
                crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

            // Compute the dummy circuit's constraint count once. This is
            // cheap (~1 ms) and guarantees that any shape change (even
            // arity-preserving ones) invalidates stale cached keys.
            let dummy_circuit = RollupCircuit::padding();
            let z0 = Self::initial_z0();
            let mut cs = TestConstraintSystem::<F1>::new();
            let z_alloc: Vec<_> = z0
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    AllocatedNum::alloc_infallible(cs.namespace(|| format!("z_{i}")), || *v)
                })
                .collect();
            dummy_circuit
                .synthesize(&mut cs, &z_alloc)
                .expect("dummy circuit synthesize must succeed");
            let expected_constraint_count = cs.num_constraints();

            // Initialize global parameters if not already loaded.
            // PublicParams are loaded from disk when available; otherwise
            // generated via the supplied closure and persisted.
            PUBLIC_PARAMS.get_or_init(|| {
                let pp = key_manager
                    .load_or_generate_ivc_pk(expected_arity, expected_constraint_count, || {
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
                    .load_or_generate_snark_keys::<E1, E2, RollupCircuit, S1, S2>(
                        expected_arity,
                        expected_constraint_count,
                        || {
                            RollupCompressedSNARK::setup(pp)
                                .expect("Failed to setup CompressedSNARK")
                        },
                    )
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

        /// Verify a Nova block proof against the **default empty-tree
        /// initial state** (`z0 = initial_z0()`).
        ///
        /// This is sound for blocks proved from the empty initial state
        /// (the first block, or unit tests). Blocks proved with a
        /// hydrated initial state (a non-empty `z0[1]`, produced by
        /// [`Self::prove_circuits_with_z0`]) MUST be verified with
        /// [`Self::verify_with_z0`] so the verifier replays the correct
        /// `z0`; verifying such a proof here will correctly **reject**
        /// it (the folding hash binds `z0`).
        ///
        /// Unlike the previous implementation, this binds the verified
        /// IVC output state `zn` to the proof's advertised roots. A
        /// verified SNARK proves a statement about *some* output state;
        /// without binding `zn` to `proof.commitments_root` /
        /// `nullifiers_root` / `historic_root_root` / `transaction_count`
        /// a caller could pair a valid proof with arbitrary advertised
        /// roots.
        fn verify(&self, proof: &Self::ProofOutput) -> Result<bool, Self::Error> {
            // Empty proof for empty block is valid by convention.
            if proof.snark_proof.is_empty() && proof.transaction_count == 0 {
                return Ok(true);
            }
            let z0 = Self::initial_z0();
            let z0: [F1; 5] = z0
                .try_into()
                .map_err(|_| ProvingError::VerificationFailed("initial_z0 arity != 5".into()))?;
            self.verify_with_z0(proof, z0)
        }
    }

    impl NovaRollupEngine {
        /// Verify a Nova block proof against an explicit initial state
        /// `z0`.
        ///
        /// This is the general, sound verification entry point. It:
        ///
        /// 1. Runs the real Spartan `CompressedSNARK::verify`, which
        ///    cryptographically attests that folding `num_steps` IVC
        ///    steps from `z0` yields the SNARK's committed output state
        ///    `zn`.
        /// 2. **Binds** `zn` to the proof's advertised roots so the
        ///    succinct proof cannot be re-used with different public
        ///    outputs.
        ///
        /// The off-chain attestor (see `NovaRollupVerifier.sol`) calls
        /// this with the same `z0` the proposer proved against (the
        /// empty-tree `z0` for the first block, or the hydrated
        /// `pre_nullifiers_root` for subsequent blocks) and signs only
        /// when it returns `Ok(true)`.
        pub fn verify_with_z0(&self, proof: &NovaProof, z0: [F1; 5]) -> Result<bool, ProvingError> {
            // Empty proof for empty block is valid by convention.
            if proof.snark_proof.is_empty() && proof.transaction_count == 0 {
                return Ok(true);
            }
            if proof.snark_proof.is_empty() {
                return Err(ProvingError::VerificationFailed(
                    "Empty snark_proof for non-empty block".into(),
                ));
            }

            // Ensure the verifying key has been loaded.
            let _ = Self::setup()?;

            // Deserialize the compressed SNARK.
            let compressed: RollupCompressedSNARK = bincode::deserialize(&proof.snark_proof)
                .map_err(|e| {
                    ProvingError::VerificationFailed(format!(
                        "CompressedSNARK deserialization: {e}"
                    ))
                })?;

            let vk = SNARK_VK.get().ok_or_else(|| {
                ProvingError::VerificationFailed("SNARK VK not initialized".into())
            })?;

            let num_steps = proof.transaction_count;

            // NOTE on `num_steps`: this uses the proof's `transaction_count`,
            // which equals the number of folded IVC steps **only when the
            // block contains no padding circuits**. The proposer's
            // `build_rollup_circuits` may emit padding steps (for dummy
            // transactions) that are folded but do not increment
            // `transaction_count`. For such blocks the caller must use
            // [`Self::verify_with_steps`] with the true folded step count.
            // (Unifying the step-count representation in `NovaProof` is a
            // tracked follow-up.)
            self.verify_inner(compressed, vk, num_steps, &z0, proof)
        }

        /// Like [`Self::verify_with_z0`] but with an explicit folded
        /// step count, for blocks whose folded step count differs from
        /// `transaction_count` (i.e. blocks that include padding
        /// circuits). The attestor obtains `num_steps` from the number
        /// of circuits it folded.
        pub fn verify_with_steps(
            &self,
            proof: &NovaProof,
            z0: [F1; 5],
            num_steps: usize,
        ) -> Result<bool, ProvingError> {
            if proof.snark_proof.is_empty() && proof.transaction_count == 0 {
                return Ok(true);
            }
            if proof.snark_proof.is_empty() {
                return Err(ProvingError::VerificationFailed(
                    "Empty snark_proof for non-empty block".into(),
                ));
            }
            let _ = Self::setup()?;
            let compressed: RollupCompressedSNARK = bincode::deserialize(&proof.snark_proof)
                .map_err(|e| {
                    ProvingError::VerificationFailed(format!(
                        "CompressedSNARK deserialization: {e}"
                    ))
                })?;
            let vk = SNARK_VK.get().ok_or_else(|| {
                ProvingError::VerificationFailed("SNARK VK not initialized".into())
            })?;
            self.verify_inner(compressed, vk, num_steps, &z0, proof)
        }

        /// Re-run the **sound** Spartan `CompressedSNARK::verify` for a
        /// block proof whose on-wire roots were rewritten to JF values by
        /// the proposer.
        ///
        /// The proposer stamps the on-chain `NovaProof` with JF roots for
        /// the contract's structural check, but the inner SNARK actually
        /// attests to the **Neptune** roots and to the hydrated IVC
        /// initial state. To run the real verification the attestor must
        /// reconstruct that original (pre-root-rewrite) statement, so the
        /// proposer forwards the Neptune roots and the hydrated
        /// `pre_nullifiers_root` (which is `z0[1]`; the rest of `z0` is the
        /// deterministic empty-tree state from [`compute_initial_z0`]).
        ///
        /// This is the check that turns the on-chain attestation gate from
        /// "trust the signer's word" into "the signer cryptographically
        /// verified the proof": the attestor MUST call this and sign only
        /// when it returns `Ok(true)`.
        ///
        /// `num_steps` is the **true folded IVC step count** (the number of
        /// circuits the proposer folded, i.e. `circuits.len()`). This is
        /// NOT generally equal to `transaction_count`: when the proposer
        /// folds padding circuits (the default, non-dynamic block size),
        /// `num_steps == block_size` while `transaction_count` counts only
        /// the real transactions. Passing the wrong `num_steps` makes the
        /// folding hash mismatch and verification (correctly) fail, so the
        /// caller must forward the real step count.
        ///
        /// Returns `Ok(true)` iff the compressed SNARK verifies **and** its
        /// proven output state matches the forwarded Neptune roots / count.
        /// Returns `Ok(false)` (fail-closed, never panics on small input)
        /// for blobs too small to be a real compressed SNARK.
        pub fn verify_attestation(
            &self,
            snark_proof: &[u8],
            neptune_commitments_root: &[u8],
            neptune_nullifiers_root: &[u8],
            neptune_historic_root_root: &[u8],
            transaction_count: usize,
            num_steps: usize,
            pre_nullifiers_root: F1,
        ) -> Result<bool, ProvingError> {
            // Empty block is valid by convention (matches `verify_with_steps`).
            if snark_proof.is_empty() && transaction_count == 0 {
                return Ok(true);
            }

            // Cheap fail-fast: a real Spartan `CompressedSNARK` is far
            // larger than this. Rejecting tiny blobs up front avoids
            // handing a garbage length-prefix to bincode (which could
            // over-allocate) before the expensive keyed setup runs. The
            // cryptographic check below remains the real gate.
            const MIN_COMPRESSED_SNARK_BYTES: usize = 512;
            if snark_proof.len() < MIN_COMPRESSED_SNARK_BYTES {
                return Ok(false);
            }

            let mut z0: [F1; 5] = compute_initial_z0()
                .try_into()
                .map_err(|_| ProvingError::VerificationFailed("initial z0 arity != 5".into()))?;
            z0[1] = pre_nullifiers_root;

            // Reconstruct the pre-rewrite proof: identical `snark_proof`
            // bytes (the rewrite preserves them) but carrying the Neptune
            // roots the SNARK actually proved, so `verify_inner`'s binding
            // of `zn` to these roots is meaningful.
            let neptune_proof = NovaProof {
                snark_proof: snark_proof.to_vec(),
                commitments_root: neptune_commitments_root.to_vec(),
                nullifiers_root: neptune_nullifiers_root.to_vec(),
                historic_root_root: neptune_historic_root_root.to_vec(),
                transaction_count,
            };

            self.verify_with_steps(&neptune_proof, z0, num_steps)
        }

        /// Shared verification core: run the Spartan `CompressedSNARK`
        /// verification and bind the proven output state `zn` to the
        /// proof's advertised roots / count.
        fn verify_inner(
            &self,
            compressed: RollupCompressedSNARK,
            vk: &nova_snark::nova::VerifierKey<E1, E2, RollupCircuit, S1, S2>,
            num_steps: usize,
            z0: &[F1],
            proof: &NovaProof,
        ) -> Result<bool, ProvingError> {
            // (1) Cryptographic verification: returns the proven output
            //     state `zn` (the primary engine's z vector).
            let zn = compressed.verify(vk, num_steps, z0).map_err(|e| {
                ProvingError::VerificationFailed(format!("CompressedSNARK::verify: {e}"))
            })?;

            // (2) Bind the proven output state to the advertised roots.
            //     `zn` is `[commitments_root, nullifiers_root,
            //     historic_root, tx_count, nullifier_count]`.
            if zn.len() < 4 {
                return Ok(false);
            }
            let roots_match = f1_to_bytes(zn[0]) == proof.commitments_root
                && f1_to_bytes(zn[1]) == proof.nullifiers_root
                && f1_to_bytes(zn[2]) == proof.historic_root_root;
            let count_matches = zn[3] == F1::from(proof.transaction_count as u64);

            Ok(roots_match && count_matches)
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
    use crate::proving::nova_v1::proof::{NovaClientProof, NovaProof};
    use crate::proving::{ProvingError, RecursiveProvingEngine};
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
pub use nova_integration::{NovaRollupEngine, RollupCircuit, E1, F1};
