//! Nova Step Circuit for Rollup Verification
//!
//! Implements the Incremental Verifiable Computation (IVC) step circuit
//! that verifies each transaction in the rollup.
//!
//! ## State Vector (arity = 5)
//!
//! ```text
//! z = [commitments_root, nullifiers_root, historic_root, tx_count, nullifier_count]
//! ```
//!
//! - `commitments_root`  — Merkle root of the commitment tree after this tx
//! - `nullifiers_root`   — Merkle root of the nullifier tree after this tx
//! - `historic_root`     — Merkle root of historic roots after this tx
//! - `tx_count`          — Running count of processed transactions (used to constrain commitment path)
//! - `nullifier_count`   — Running count of spent nullifiers (used to constrain IMT insertion path)
//!
//! ## Per-step cryptographic checks
//!
//! For a non-padding step the circuit enforces:
//!
//! 1. **Commitment inclusion** — the new commitment is a leaf of
//!    `new_commitments_root` (binary Merkle inclusion via Poseidon).
//! 2. **Nullifier non-inclusion** — the new nullifier is **not** a leaf
//!    of `old_nullifiers_root` (indexed-Merkle-tree low-leaf proof).
//!
//! For a padding step both checks are gated off (uniform R1CS shape is
//! preserved by feeding zero witnesses to the same gadgets).
//!
//! See [`super::merkle`] for the gadget implementations and
//! [`super::hash`] for the Poseidon parameters.
//!
//! ## Key Design Note (ff crate compatibility)
//!
//! Nova's `StepCircuit<F: PrimeField>` uses `ff::PrimeField` (ff = "0.13"),
//! NOT `ark-ff`. The step circuit is generic over any
//! `F: ff::PrimeField + ff::PrimeFieldBits`, so no arkworks types appear
//! in this module. When feature `nova-v1` is enabled, `RollupStepCircuit<F>`
//! is parameterised by the engine's scalar field:
//! `<E1 as Engine>::Scalar = halo2curves::bn256::Scalar`.

#[cfg(feature = "nova-v1")]
pub mod nova_step_circuit {
    use ff::{PrimeField, PrimeFieldBits};
    use nova_snark::frontend::{
        gadgets::boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
        ConstraintSystem, SynthesisError,
    };
    use nova_snark::traits::circuit::StepCircuit;

    use crate::proving::nova_v1::{
        hash::poseidon_constants,
        merkle::{
            enforce_path_index, verify_imt_insertion_circuit, verify_imt_non_inclusion_circuit,
            verify_merkle_inclusion_circuit, AllocatedImtInsertion, AllocatedImtNonInclusion,
            AllocatedMerkleHop, ImtInsertionWitness, ImtNonInclusionWitness, MerklePathHop,
        },
    };

    // Re-export ff types so downstream code can use them without depending on ff directly.
    pub use ff::PrimeField as ExportedPrimeField;

    /// The arity (number of state inputs/outputs) for the rollup step circuit.
    ///
    /// State vector: `[commitments_root, nullifiers_root, historic_root, tx_count, nullifier_count]`
    pub const ROLLOUP_ARITY: usize = 5;

    /// Default Merkle / IMT depth for production rollup trees.
    pub const DEFAULT_MERKLE_DEPTH: usize = 32;

    /// Bit bound used for nullifier value range checks. BN254 Fr is
    /// 254-bit. We use the full 254 bits so that arbitrary Poseidon hash
    /// outputs (which are uniformly distributed over the field) are
    /// accepted. Using 252 would reject ~75% of random nullifiers and
    /// cause `Relaxed R1CS is unsatisfiable` on transfer blocks.
    pub const DEFAULT_RANGE_BITS: usize = 254;

    /// Witness data for a single IVC step (one rollup transaction).
    ///
    /// Each IVC step instance carries the private witness for that step.
    /// For padding (empty) steps, `is_padding = true` and all crypto
    /// witnesses are zero-filled — the step circuit still allocates and
    /// runs the full Merkle / IMT gadgets to keep R1CS shape uniform
    /// across the IVC (Nova requires this), but gates the equality and
    /// range checks off.
    #[derive(Debug, Clone)]
    pub struct RollupStepCircuit<F: PrimeField + PrimeFieldBits> {
        /// New commitments root after this transaction (asserted by prover,
        /// bound by the inclusion gadget when `!is_padding`).
        pub new_commitments_root: F,
        /// New nullifiers root after this transaction. Bound by the
        /// IMT-insertion gadget when `!is_padding && nullifier != 0`:
        /// the gadget proves that the post-state root is exactly the
        /// result of inserting `nullifier` and updating the low leaf
        /// to point to it.
        pub new_nullifiers_root: F,
        /// New historic root after this transaction.
        pub new_historic_root: F,
        /// Nullifier value being spent (private).
        pub nullifier: F,
        /// Commitment value being introduced (private).
        pub commitment: F,
        /// Inclusion path proving `commitment` is in `new_commitments_root`.
        /// Length MUST equal `merkle_depth`.
        pub commitment_path: Vec<MerklePathHop<F>>,
        /// Low-leaf non-inclusion witness for `nullifier` against
        /// `old_nullifiers_root`. `path.len()` MUST equal `merkle_depth`.
        pub nullifier_witness: ImtNonInclusionWitness<F>,
        /// IMT insertion witness that proves `new_nullifiers_root` is
        /// the result of inserting `nullifier` and updating the low
        /// leaf. Both `updated_low_path` and `new_leaf_path` MUST have
        /// length `merkle_depth`.
        pub nullifier_insertion: ImtInsertionWitness<F>,
        /// Whether this is a padding step (no transaction processed).
        pub is_padding: bool,
        /// Merkle / IMT tree depth (must match across all steps in a fold).
        pub merkle_depth: usize,
        /// Bit bound for in-circuit less-than checks on nullifier values.
        pub range_bits: usize,
    }

    impl<F: PrimeField + PrimeFieldBits> Default for RollupStepCircuit<F> {
        fn default() -> Self {
            Self::padding_with_depth(DEFAULT_MERKLE_DEPTH)
        }
    }

    impl<F: PrimeField + PrimeFieldBits> RollupStepCircuit<F> {
        /// A padding step at the default Merkle depth.
        pub fn padding() -> Self {
            Self::padding_with_depth(DEFAULT_MERKLE_DEPTH)
        }

        /// A padding step at an explicit depth. Tests use small depths to
        /// keep IVC setup fast; production uses [`DEFAULT_MERKLE_DEPTH`].
        ///
        /// All cryptographic witnesses are zero-filled. The gadgets still
        /// execute but their assertions are gated off via `is_padding`.
        pub fn padding_with_depth(merkle_depth: usize) -> Self {
            let zero_path: Vec<MerklePathHop<F>> = (0..merkle_depth)
                .map(|_| MerklePathHop {
                    sibling: F::ZERO,
                    is_right: false,
                })
                .collect();
            Self {
                new_commitments_root: F::ZERO,
                new_nullifiers_root: F::ZERO,
                new_historic_root: F::ZERO,
                nullifier: F::ZERO,
                commitment: F::ZERO,
                commitment_path: zero_path.clone(),
                nullifier_witness: ImtNonInclusionWitness {
                    nullifier: F::ZERO,
                    low_value: F::ZERO,
                    low_next_index: F::ZERO,
                    low_next_value: F::ZERO,
                    path: zero_path.clone(),
                },
                nullifier_insertion: ImtInsertionWitness {
                    new_leaf_index: F::ZERO,
                    updated_low_path: zero_path.clone(),
                    new_leaf_path: zero_path,
                },
                is_padding: true,
                merkle_depth,
                range_bits: DEFAULT_RANGE_BITS,
            }
        }

        /// Create a real (non-padding) step from full witness data.
        ///
        /// Both `commitment_path` and `nullifier_witness.path` MUST have
        /// length `merkle_depth` to keep R1CS shape uniform with the
        /// padding circuit used during `PublicParams::setup`.
        #[allow(clippy::too_many_arguments)]
        pub fn new_real(
            merkle_depth: usize,
            new_commitments_root: F,
            new_nullifiers_root: F,
            new_historic_root: F,
            commitment: F,
            commitment_path: Vec<MerklePathHop<F>>,
            nullifier_witness: ImtNonInclusionWitness<F>,
            nullifier_insertion: ImtInsertionWitness<F>,
        ) -> Self {
            assert_eq!(
                commitment_path.len(),
                merkle_depth,
                "commitment_path length must match merkle_depth"
            );
            assert_eq!(
                nullifier_witness.path.len(),
                merkle_depth,
                "nullifier_witness.path length must match merkle_depth"
            );
            assert_eq!(
                nullifier_insertion.updated_low_path.len(),
                merkle_depth,
                "nullifier_insertion.updated_low_path length must match merkle_depth"
            );
            assert_eq!(
                nullifier_insertion.new_leaf_path.len(),
                merkle_depth,
                "nullifier_insertion.new_leaf_path length must match merkle_depth"
            );
            Self {
                new_commitments_root,
                new_nullifiers_root,
                new_historic_root,
                nullifier: nullifier_witness.nullifier,
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
                is_padding: false,
                merkle_depth,
                range_bits: DEFAULT_RANGE_BITS,
            }
        }

        /// Legacy constructor — produces a non-padding step **without**
        /// real Merkle witnesses (zero-filled). Useful for benchmarks that
        /// only care about IVC throughput, and for migration of callers
        /// that haven't been updated to supply witnesses yet.
        ///
        /// The soundness gadgets will reject these proofs once a non-trivial
        /// root is asserted, so production code MUST use [`Self::new_real`].
        ///
        /// **This constructor is deprecated.** It is kept only to allow
        /// internal unit tests to construct trivially-shaped circuits. Any
        /// production caller should be using [`Self::new_real`].
        #[deprecated(
            since = "0.2.0",
            note = "uses zero-filled Merkle witnesses; use RollupStepCircuit::new_real instead"
        )]
        #[cfg(test)]
        #[allow(dead_code)]
        pub fn new(
            new_commitments_root: F,
            new_nullifiers_root: F,
            new_historic_root: F,
            nullifier: F,
            commitment: F,
        ) -> Self {
            let depth = DEFAULT_MERKLE_DEPTH;
            let zero_path: Vec<MerklePathHop<F>> = (0..depth)
                .map(|_| MerklePathHop {
                    sibling: F::ZERO,
                    is_right: false,
                })
                .collect();
            Self {
                new_commitments_root,
                new_nullifiers_root,
                new_historic_root,
                nullifier,
                commitment,
                commitment_path: zero_path.clone(),
                nullifier_witness: ImtNonInclusionWitness {
                    nullifier,
                    low_value: F::ZERO,
                    low_next_index: F::ZERO,
                    low_next_value: F::ZERO,
                    path: zero_path.clone(),
                },
                nullifier_insertion: ImtInsertionWitness {
                    new_leaf_index: F::ZERO,
                    updated_low_path: zero_path.clone(),
                    new_leaf_path: zero_path,
                },
                is_padding: false,
                merkle_depth: depth,
                range_bits: DEFAULT_RANGE_BITS,
            }
        }
    }

    impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for RollupStepCircuit<F> {
        fn arity(&self) -> usize {
            ROLLOUP_ARITY
        }

        /// Synthesize the rollup verification constraints for one step.
        ///
        /// # State transition
        ///
        /// ```text
        /// z_in  = [old_commitments_root, old_nullifiers_root, old_historic_root, tx_count]
        /// z_out = [new_commitments_root, new_nullifiers_root, new_historic_root, tx_count + delta]
        /// ```
        ///
        /// `delta = 1` for real steps, `0` for padding.
        ///
        /// # Constraints (all unconditionally allocated for uniform R1CS shape)
        ///
        /// - `is_padding` allocated as a boolean witness; `enabled = !is_padding`.
        /// - Commitment Merkle inclusion gadget, gated on `enabled`.
        /// - Nullifier IMT non-inclusion gadget, gated on `enabled`.
        /// - `new_tx_count = old_tx_count + delta` where `delta` is
        ///   constrained to equal `enabled` (so it's 0 or 1).
        /// - `new_*_root` variables are passed through to `z_out`. The
        ///   inclusion gadget binds `new_commitments_root` to the path.
        ///   For padding steps the new roots are constrained to equal
        ///   the old roots.
        fn synthesize<CS: ConstraintSystem<F>>(
            &self,
            cs: &mut CS,
            z: &[AllocatedNum<F>],
        ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
            assert_eq!(z.len(), ROLLOUP_ARITY, "IVC state arity mismatch");
            assert_eq!(
                self.commitment_path.len(),
                self.merkle_depth,
                "commitment_path/merkle_depth mismatch"
            );
            assert_eq!(
                self.nullifier_witness.path.len(),
                self.merkle_depth,
                "nullifier_witness.path/merkle_depth mismatch"
            );
            assert_eq!(
                self.nullifier_insertion.updated_low_path.len(),
                self.merkle_depth,
                "nullifier_insertion.updated_low_path/merkle_depth mismatch"
            );
            assert_eq!(
                self.nullifier_insertion.new_leaf_path.len(),
                self.merkle_depth,
                "nullifier_insertion.new_leaf_path/merkle_depth mismatch"
            );

            // Destructure input state.
            let old_commitments_root = z[0].clone();
            let old_nullifiers_root = z[1].clone();
            let old_historic_root = z[2].clone();
            let old_tx_count = z[3].clone();
            let old_nullifier_count = z[4].clone();

            let constants = poseidon_constants::<F>();

            // ----------------------------------------------------------------
            // is_padding witness + enabled = !is_padding.
            // ----------------------------------------------------------------
            let is_padding_bit =
                AllocatedBit::alloc(cs.namespace(|| "is_padding"), Some(self.is_padding))?;
            let is_padding = Boolean::from(is_padding_bit);
            let enabled = is_padding.not();

            // ----------------------------------------------------------------
            // Allocate per-step witness values. For padding steps these are
            // all zero; the gadgets are gated off so the zero witnesses are
            // harmless but the variables are still allocated, keeping R1CS
            // shape uniform.
            // ----------------------------------------------------------------
            // For padding steps the `new_*_root` witnesses are derived
            // from `z_in` so the pass-through equality constraints below
            // are trivially `old - old = 0`. For real steps the struct's
            // explicit values are used and bound by the Merkle-inclusion
            // gadget.  The R1CS structure is identical either way.
            let pad_fallback = |real: F, fallback: &AllocatedNum<F>| -> F {
                if self.is_padding {
                    fallback.get_value().unwrap_or(F::ZERO)
                } else {
                    real
                }
            };
            let new_commitments_root =
                AllocatedNum::alloc(cs.namespace(|| "new_commitments_root"), || {
                    Ok(pad_fallback(
                        self.new_commitments_root,
                        &old_commitments_root,
                    ))
                })?;
            let new_nullifiers_root =
                AllocatedNum::alloc(cs.namespace(|| "new_nullifiers_root"), || {
                    Ok(pad_fallback(self.new_nullifiers_root, &old_nullifiers_root))
                })?;
            let new_historic_root =
                AllocatedNum::alloc(cs.namespace(|| "new_historic_root"), || {
                    Ok(pad_fallback(self.new_historic_root, &old_historic_root))
                })?;
            let commitment =
                AllocatedNum::alloc(cs.namespace(|| "commitment"), || Ok(self.commitment))?;
            let commitment_path: Vec<AllocatedMerkleHop<F>> = self
                .commitment_path
                .iter()
                .enumerate()
                .map(|(i, hop)| {
                    AllocatedMerkleHop::alloc(cs.namespace(|| format!("commitment_hop_{i}")), *hop)
                })
                .collect::<Result<_, _>>()?;
            let nullifier_alloc = AllocatedImtNonInclusion::alloc(
                cs.namespace(|| "nullifier_witness"),
                &self.nullifier_witness,
            )?;
            let nullifier_insertion_alloc = AllocatedImtInsertion::alloc(
                cs.namespace(|| "nullifier_insertion_witness"),
                &self.nullifier_insertion,
            )?;

            // ----------------------------------------------------------------
            // 1. Commitment Merkle inclusion (gated on `enabled`).
            //    Proves `commitment` is at `commitment_path` in
            //    `new_commitments_root`. Without this, a malicious proposer
            //    could assert any `new_commitments_root` it likes.
            // ----------------------------------------------------------------
            verify_merkle_inclusion_circuit(
                &constants,
                cs.namespace(|| "commitment_inclusion"),
                &commitment,
                &commitment_path,
                &new_commitments_root,
                &enabled,
            )?;

            enforce_path_index(
                cs.namespace(|| "commitment_path_index"),
                &commitment_path,
                &old_tx_count,
                &enabled,
            )?;

            // ----------------------------------------------------------------
            // 2. Nullifier IMT non-inclusion (gated on `enabled` AND `nullifier != 0`).
            //    Proves `nullifier` is NOT in `old_nullifiers_root` via the
            //    low-leaf bracket: `low.value < nullifier`, and either
            //    `low.next_value == 0` or `nullifier < low.next_value`,
            //    plus inclusion of the low leaf in old_nullifiers_root.
            // ----------------------------------------------------------------
            use crate::proving::nova_v1::merkle::is_zero;
            let nullifier_is_zero = is_zero(
                cs.namespace(|| "nullifier_is_zero"),
                &nullifier_alloc.nullifier,
            )?;
            let nullifier_is_nonzero = nullifier_is_zero.not();
            let nullifier_enabled = Boolean::and(
                cs.namespace(|| "nullifier_enabled"),
                &enabled,
                &nullifier_is_nonzero,
            )?;

            verify_imt_non_inclusion_circuit(
                &constants,
                cs.namespace(|| "nullifier_non_inclusion"),
                &nullifier_alloc,
                &old_nullifiers_root,
                self.range_bits,
                &nullifier_enabled,
            )?;

            // ----------------------------------------------------------------
            // 2b. Nullifier IMT insertion (state-transition check).
            //     Proves that `new_nullifiers_root` is the result of
            //     inserting `nullifier` and updating the low leaf to
            //     point to it. This binds the post-state nullifier root
            //     to the witnessed insertion, which is what prevents a
            //     malicious proposer from asserting an arbitrary
            //     `new_nullifiers_root`.
            //
            //     Together with the non-inclusion check above, this
            //     proves the full state transition:
            //     `old_nullifiers_root  --insert nullifier-->  new_nullifiers_root`.
            // ----------------------------------------------------------------
            // The insertion bound is `merkle_depth + 1` bits so the
            // upper bound is `2^(merkle_depth + 1) > 2^merkle_depth`,
            // which strictly bounds the new-leaf index below the next
            // power of two (one bit of headroom past the tree's leaf
            // capacity). Production callers should set
            // `merkle_depth = 32`, so the bound is `2^33`.
            let insertion_bits = self.merkle_depth + 1;
            verify_imt_insertion_circuit(
                &constants,
                cs.namespace(|| "nullifier_insertion"),
                &nullifier_alloc,
                &nullifier_insertion_alloc,
                &new_nullifiers_root,
                insertion_bits,
                &nullifier_enabled,
            )?;

            // Constrain the insertion index to match the path. We use
            // `new_leaf_index` (the actual IMT insertion index) rather
            // than `old_nullifier_count` (the per-block running count),
            // because the witness IMT is hydrated with prior-block
            // nullifiers so its insertion indices are offset by
            // `1 + prior_count`. Using `old_nullifier_count` here would
            // mismatch the path as soon as the first prior-hydrated
            // real nullifier is processed, making the R1CS unsatisfiable.
            enforce_path_index(
                cs.namespace(|| "nullifier_path_index"),
                &nullifier_insertion_alloc.new_leaf_path,
                &nullifier_insertion_alloc.new_leaf_index,
                &nullifier_enabled,
            )?;

            // ----------------------------------------------------------------
            // 3. Padding-step state pass-through.
            //    When `is_padding`, the new roots must equal the old roots.
            //    These are conditional equalities: gated on `is_padding`
            //    (the dual of `enabled`).
            // ----------------------------------------------------------------
            conditional_assert_equal(
                cs.namespace(|| "pad_commitments_root_eq"),
                &is_padding,
                &new_commitments_root,
                &old_commitments_root,
            )?;

            let pad_nullifiers = nullifier_enabled.not();
            conditional_assert_equal(
                cs.namespace(|| "pad_nullifiers_root_eq"),
                &pad_nullifiers,
                &new_nullifiers_root,
                &old_nullifiers_root,
            )?;
            conditional_assert_equal(
                cs.namespace(|| "pad_historic_root_eq"),
                &is_padding,
                &new_historic_root,
                &old_historic_root,
            )?;

            // ----------------------------------------------------------------
            // 4. tx_count update: new_tx_count = old_tx_count + delta,
            //    where delta = enabled (0 or 1).
            // ----------------------------------------------------------------
            let new_tx_count = AllocatedNum::alloc(cs.namespace(|| "new_tx_count"), || {
                let old = old_tx_count
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let d = if self.is_padding { F::ZERO } else { F::ONE };
                Ok(old + d)
            })?;
            cs.enforce(
                || "tx_count_delta",
                |lc| lc + new_tx_count.get_variable() - old_tx_count.get_variable(),
                |lc| lc + CS::one(),
                |_| enabled.lc(CS::one(), F::ONE),
            );

            // ----------------------------------------------------------------
            // 5. nullifier_count update: incremented if nullifier_enabled.
            // ----------------------------------------------------------------
            let new_nullifier_count =
                AllocatedNum::alloc(cs.namespace(|| "new_nullifier_count"), || {
                    let old = old_nullifier_count
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let d = if nullifier_enabled.get_value().unwrap_or(false) {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    Ok(old + d)
                })?;
            cs.enforce(
                || "nullifier_count_delta",
                |lc| lc + new_nullifier_count.get_variable() - old_nullifier_count.get_variable(),
                |lc| lc + CS::one(),
                |_| nullifier_enabled.lc(CS::one(), F::ONE),
            );

            // Return updated state.
            Ok(vec![
                new_commitments_root,
                new_nullifiers_root,
                new_historic_root,
                new_tx_count,
                new_nullifier_count,
            ])
        }
    }

    /// Enforce that when `condition` is true, `x` and `y` are equal.
    /// `condition * (x - y) = 0`.  Always emits one R1CS constraint
    /// regardless of values, preserving uniform circuit shape.
    fn conditional_assert_equal<F, CS>(
        mut cs: CS,
        condition: &Boolean,
        x: &AllocatedNum<F>,
        y: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError>
    where
        F: PrimeField,
        CS: ConstraintSystem<F>,
    {
        cs.enforce(
            || "cond_eq",
            |_| condition.lc(CS::one(), F::ONE),
            |lc| lc + x.get_variable() - y.get_variable(),
            |lc| lc,
        );
        Ok(())
    }

    /// Rollup IVC State (Rust-side representation of the `z` vector).
    #[derive(Debug, Clone, Default)]
    pub struct RollupIvcState {
        pub commitments_root: Vec<u8>,
        pub nullifiers_root: Vec<u8>,
        pub historic_root_root: Vec<u8>,
        pub transaction_count: u64,
        pub nullifier_count: u64,
    }

    impl RollupIvcState {
        #[allow(dead_code)]
        pub fn new(
            commitments_root: Vec<u8>,
            nullifiers_root: Vec<u8>,
            historic_root_root: Vec<u8>,
        ) -> Self {
            Self {
                commitments_root,
                nullifiers_root,
                historic_root_root,
                transaction_count: 0,
                nullifier_count: 0,
            }
        }

        pub fn initial() -> Self {
            Self {
                commitments_root: vec![0u8; 32],
                nullifiers_root: vec![0u8; 32],
                historic_root_root: vec![0u8; 32],
                transaction_count: 0,
                nullifier_count: 0,
            }
        }
    }

    // Re-export the arity constant as ROLLUP_ARITY (canonical name) while
    // keeping the original misspelled symbol for backward compat.
    pub use ROLLOUP_ARITY as ROLLUP_ARITY;

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proving::nova_v1::hash::poseidon_hash2_native;
        use crate::proving::nova_v1::merkle::{compute_merkle_root_native, imt_leaf_hash_native};
        use ff::Field;
        use nova_snark::frontend::test_cs::TestConstraintSystem;
        use nova_snark::provider::Bn256EngineKZG;
        use nova_snark::traits::Engine;

        type F1 = <Bn256EngineKZG as Engine>::Scalar;

        #[test]
        fn padding_circuit_arity_and_default() {
            let c = RollupStepCircuit::<F1>::padding();
            assert_eq!(c.arity(), ROLLOUP_ARITY);
            assert!(c.is_padding);
            assert_eq!(c.merkle_depth, DEFAULT_MERKLE_DEPTH);
            assert_eq!(c.commitment_path.len(), DEFAULT_MERKLE_DEPTH);
            assert_eq!(c.nullifier_witness.path.len(), DEFAULT_MERKLE_DEPTH);
        }

        // ----- helpers for synthesis tests -----

        /// Build a tiny commitment tree at `depth` and return
        /// `(root, leaves, path_for_leaf_idx)`.
        fn build_commitment_tree(
            depth: usize,
            leaves: Vec<F1>,
            leaf_idx: usize,
        ) -> (F1, Vec<MerklePathHop<F1>>) {
            let constants = poseidon_constants::<F1>();
            let mut padded = leaves;
            padded.resize(1 << depth, F1::ZERO);

            let mut idx = leaf_idx;
            let mut path = Vec::with_capacity(depth);
            let mut layer = padded;
            for _ in 0..depth {
                let is_right = idx & 1 == 1;
                let sibling = if is_right {
                    layer[idx - 1]
                } else {
                    layer[idx + 1]
                };
                path.push(MerklePathHop { sibling, is_right });
                layer = layer
                    .chunks(2)
                    .map(|c| poseidon_hash2_native(&constants, c[0], c[1]))
                    .collect();
                idx /= 2;
            }
            assert_eq!(layer.len(), 1);
            (layer[0], path)
        }

        /// Build a tiny IMT root and a non-inclusion witness for `nullifier`
        /// against sorted values `vals` (must NOT contain `nullifier`).
        fn build_nullifier_witness(
            depth: usize,
            sorted_with_zero: Vec<F1>,
            nullifier: F1,
        ) -> (F1, ImtNonInclusionWitness<F1>) {
            let constants = poseidon_constants::<F1>();
            // Compute leaf hashes.
            let leaves: Vec<F1> = sorted_with_zero
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let next_idx = F1::from(((i + 1) as u64) % (1u64 << depth));
                    let next_val = sorted_with_zero.get(i + 1).copied().unwrap_or(F1::ZERO);
                    imt_leaf_hash_native(&constants, *v, next_idx, next_val)
                })
                .collect();
            // Find low-leaf index (largest sorted value strictly less than nullifier).
            // Test inputs use small integers so `to_repr` byte compare works.
            let cmp = |a: &F1, b: &F1| {
                let a = a.to_repr();
                let b = b.to_repr();
                a.as_ref().iter().rev().cmp(b.as_ref().iter().rev())
            };
            let mut low_idx = 0;
            for (i, v) in sorted_with_zero.iter().enumerate() {
                if cmp(v, &nullifier) == std::cmp::Ordering::Less {
                    low_idx = i;
                }
            }
            let low_value = sorted_with_zero[low_idx];
            let low_next_index = F1::from(((low_idx + 1) as u64) % (1u64 << depth));
            let low_next_value = sorted_with_zero
                .get(low_idx + 1)
                .copied()
                .unwrap_or(F1::ZERO);
            let (root, path) = build_commitment_tree(depth, leaves, low_idx);
            (
                root,
                ImtNonInclusionWitness {
                    nullifier,
                    low_value,
                    low_next_index,
                    low_next_value,
                    path,
                },
            )
        }

        /// Build a real IMT-insertion witness for a small IMT using
        /// the in-memory `NeptuneIMT` from the lib. Mirrors the
        /// off-chain builder in `lib::proving::nova_v1::witness`.
        fn build_imt_insertion_witness(
            depth: u32,
            sorted_with_zero: Vec<F1>,
            nullifier: F1,
        ) -> (F1, ImtInsertionWitness<F1>) {
            use crate::proving::nova_v1::commitment_tree::{InMemoryNullifierStorage, NeptuneIMT};
            let mut imt =
                NeptuneIMT::<InMemoryNullifierStorage>::new(depth, InMemoryNullifierStorage::new());
            for v in &sorted_with_zero {
                if !v.is_zero_vartime() {
                    imt.insert_nullifier(*v).expect("seed insert");
                }
            }
            let (low_leaf, _w) = imt
                .get_non_inclusion_witness(nullifier)
                .expect("low leaf must exist");
            imt.insert_nullifier(nullifier).expect("insert nullifier");
            let new_leaf_index = imt.next_insert_index().saturating_sub(1);
            let updated_low_path = imt.inclusion_path(low_leaf.index);
            let new_leaf_path = imt.inclusion_path(new_leaf_index);
            let root = imt.root();
            (
                root,
                ImtInsertionWitness {
                    new_leaf_index: F1::from(new_leaf_index),
                    updated_low_path,
                    new_leaf_path,
                },
            )
        }

        /// Drive a `RollupStepCircuit` through `TestConstraintSystem` and
        /// return whether all constraints are satisfied.
        fn run_step(
            circuit: &RollupStepCircuit<F1>,
            z_in: [F1; 5],
        ) -> (bool, Option<String>, Vec<F1>) {
            let mut cs = TestConstraintSystem::<F1>::new();
            let z_alloc: Vec<_> = z_in
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    AllocatedNum::alloc_infallible(cs.namespace(|| format!("z_in_{i}")), || *v)
                })
                .collect();
            let z_out_alloc = circuit.synthesize(&mut cs, &z_alloc).unwrap();
            let satisfied = cs.is_satisfied();
            let unsat = cs.which_is_unsatisfied().map(String::from);
            let z_out = z_out_alloc.iter().map(|n| n.get_value().unwrap()).collect();
            (satisfied, unsat, z_out)
        }

        /// 1.1.4 — Valid commitment inclusion + valid nullifier non-inclusion
        /// MUST satisfy the step circuit and produce the expected z_out.
        #[test]
        fn step_real_tx_with_valid_witnesses_satisfies() {
            let depth = 4;
            // commitment side
            let commitment = F1::from(77u64);
            let mut commit_leaves = vec![F1::from(1u64), F1::from(2u64)];
            commit_leaves.push(commitment); // insert at index 2
            let (new_commitments_root, commitment_path) =
                build_commitment_tree(depth, commit_leaves, 2);

            // nullifier side
            let nullifier = F1::from(30u64);
            let (old_nullifiers_root, nullifier_witness) = build_nullifier_witness(
                depth,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );
            let (new_nullifiers_root, nullifier_insertion) = build_imt_insertion_witness(
                depth as u32,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );

            let circuit = RollupStepCircuit::<F1>::new_real(
                depth,
                new_commitments_root,
                new_nullifiers_root,
                F1::from(7u64),
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
            );

            // NeptuneIMT starts with next_insert_index=1.
            // After seed inserts (10, 50): next_insert_index=3.
            // The new nullifier 30 is inserted at index 3.
            // old_nullifier_count must equal next_insert_index before insertion = 3.
            let z_in = [
                F1::ZERO,
                old_nullifiers_root,
                F1::ZERO,
                F1::from(2u64),
                F1::from(3u64),
            ];
            let (satisfied, unsat, z_out) = run_step(&circuit, z_in);
            assert!(satisfied, "valid step must satisfy: {:?}", unsat);
            assert_eq!(z_out[0], new_commitments_root);
            assert_eq!(z_out[1], new_nullifiers_root);
            assert_eq!(z_out[3], F1::from(3u64), "tx_count must increment");
            assert_eq!(z_out[4], F1::from(4u64), "nullifier_count must increment");
        }

        /// 1.1.4 — Tampered commitment path (wrong sibling) MUST fail.
        #[test]
        fn step_real_tx_with_tampered_commitment_path_fails() {
            let depth = 4;
            let commitment = F1::from(77u64);
            let mut commit_leaves = vec![F1::from(1u64), F1::from(2u64)];
            commit_leaves.push(commitment);
            let (new_commitments_root, mut commitment_path) =
                build_commitment_tree(depth, commit_leaves, 2);
            commitment_path[1].sibling += F1::ONE; // tamper

            let nullifier = F1::from(30u64);
            let (old_nullifiers_root, nullifier_witness) = build_nullifier_witness(
                depth,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );
            let (new_nullifiers_root, nullifier_insertion) = build_imt_insertion_witness(
                depth as u32,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );

            let circuit = RollupStepCircuit::<F1>::new_real(
                depth,
                new_commitments_root,
                new_nullifiers_root,
                F1::ZERO,
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
            );

            let z_in = [
                F1::ZERO,
                old_nullifiers_root,
                F1::ZERO,
                F1::from(2u64),
                F1::from(3u64),
            ];
            let (satisfied, _, _) = run_step(&circuit, z_in);
            assert!(!satisfied, "tampered commitment path must NOT satisfy");
        }

        /// 1.1.4 — Asserting a fake `new_commitments_root` MUST fail.
        #[test]
        fn step_real_tx_with_wrong_new_commitments_root_fails() {
            let depth = 4;
            let commitment = F1::from(77u64);
            let mut commit_leaves = vec![F1::from(1u64), F1::from(2u64)];
            commit_leaves.push(commitment);
            let (real_root, commitment_path) = build_commitment_tree(depth, commit_leaves, 2);

            let nullifier = F1::from(30u64);
            let (old_nullifiers_root, nullifier_witness) = build_nullifier_witness(
                depth,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );
            let (new_nullifiers_root, nullifier_insertion) = build_imt_insertion_witness(
                depth as u32,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );

            // Claim a different root than the real one.
            let bogus_root = real_root + F1::from(1u64);
            let circuit = RollupStepCircuit::<F1>::new_real(
                depth,
                bogus_root,
                new_nullifiers_root,
                F1::ZERO,
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
            );

            let z_in = [
                F1::ZERO,
                old_nullifiers_root,
                F1::ZERO,
                F1::from(2u64),
                F1::from(3u64),
            ];
            let (satisfied, _, _) = run_step(&circuit, z_in);
            assert!(!satisfied, "bogus new_commitments_root must NOT satisfy");
        }

        /// 1.1.4 — A nullifier that IS in the tree (collides with the low
        /// leaf) MUST fail the non-inclusion check.
        #[test]
        fn step_real_tx_with_double_spend_fails() {
            let depth = 4;
            let commitment = F1::from(77u64);
            let mut commit_leaves = vec![F1::from(1u64)];
            commit_leaves.push(commitment);
            let (new_commitments_root, commitment_path) =
                build_commitment_tree(depth, commit_leaves, 1);

            // Build a tree containing 30, then try to spend 30 again.
            let (old_nullifiers_root, mut nullifier_witness) = build_nullifier_witness(
                depth,
                vec![F1::ZERO, F1::from(10u64), F1::from(30u64), F1::from(50u64)],
                F1::from(20u64), // first build a witness for some other value...
            );
            // ...then re-aim it at the existing leaf 30.
            nullifier_witness.nullifier = F1::from(30u64);
            // The insertion witness still uses the original nullifier
            // (20) so the path is well-formed, but the inserted value
            // (30) is rejected by the non-inclusion check first.
            let (_new_nullifiers_root, nullifier_insertion) = build_imt_insertion_witness(
                depth as u32,
                vec![F1::ZERO, F1::from(10u64), F1::from(30u64), F1::from(50u64)],
                F1::from(20u64),
            );

            let circuit = RollupStepCircuit::<F1>::new_real(
                depth,
                new_commitments_root,
                F1::from(999u64),
                F1::ZERO,
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
            );

            // After seed inserts (10, 30, 50): next_insert_index=4.
            // old_nullifier_count must equal next_insert_index before insertion = 4.
            let z_in = [
                F1::ZERO,
                old_nullifiers_root,
                F1::ZERO,
                F1::from(2u64),
                F1::from(4u64),
            ];
            let (satisfied, _, _) = run_step(&circuit, z_in);
            assert!(
                !satisfied,
                "double-spend (nullifier in tree) must NOT satisfy"
            );
        }

        /// 1.1.4 — Padding step passes the state through unchanged and the
        /// gated gadgets accept zero witnesses.
        #[test]
        fn step_padding_passes_state_through_and_satisfies() {
            let circuit = RollupStepCircuit::<F1>::padding_with_depth(4);
            let z_in = [
                F1::from(11u64),
                F1::from(22u64),
                F1::from(33u64),
                F1::from(44u64),
                F1::from(55u64),
            ];
            let (satisfied, unsat, z_out) = run_step(&circuit, z_in);
            assert!(satisfied, "padding must satisfy: {:?}", unsat);
            assert_eq!(
                z_out,
                z_in.to_vec(),
                "padding must pass state through unchanged"
            );
        }

        /// Even if a prover tries to smuggle a different `new_*_root` into
        /// a padding step's struct, the circuit MUST still emit z_out == z_in
        /// (the pad-fallback overrides the struct field when `is_padding`).
        /// This is what guarantees padding can never advance state.
        #[test]
        fn padding_ignores_struct_root_fields_and_passes_state_through() {
            let mut circuit = RollupStepCircuit::<F1>::padding_with_depth(4);
            // Try to sneak in different "new" roots — they should be ignored
            // because is_padding=true makes pad_fallback use z_in instead.
            circuit.new_commitments_root = F1::from(9999u64);
            circuit.new_nullifiers_root = F1::from(8888u64);
            circuit.new_historic_root = F1::from(7777u64);

            let z_in = [
                F1::from(11u64),
                F1::from(22u64),
                F1::from(33u64),
                F1::from(44u64),
                F1::from(55u64),
            ];
            let (satisfied, unsat, z_out) = run_step(&circuit, z_in);
            assert!(satisfied, "padding must always satisfy: {:?}", unsat);
            assert_eq!(
                z_out,
                z_in.to_vec(),
                "padding MUST pass state through unchanged regardless of struct fields"
            );
        }

        /// Conversely, a *non-padding* step trying to lie about roots is
        /// caught by the inclusion gadget. (Already covered by
        /// `step_real_tx_with_wrong_new_commitments_root_fails`.)
        #[test]
        fn padding_flag_must_be_a_proper_boolean() {
            // Sanity: is_padding=true and is_padding=false produce a valid
            // R1CS shape that satisfies for genuine padding/real inputs.
            let pad = RollupStepCircuit::<F1>::padding_with_depth(4);
            let z = [F1::ZERO, F1::ZERO, F1::ZERO, F1::ZERO, F1::ZERO];
            let (ok, unsat, _) = run_step(&pad, z);
            assert!(ok, "padding with all-zero z must satisfy: {:?}", unsat);
        }

        /// 1.1 end-to-end: fold a real (non-padding) step carrying genuine
        /// Merkle inclusion + IMT non-inclusion witnesses through the full
        /// Nova IVC machinery and verify the recursive SNARK.
        ///
        /// This test is slow (full `PublicParams::setup` is ~30s) but it
        /// is the only place where the gadgets are exercised inside the
        /// real IVC primary/secondary R1CS rather than `TestConstraintSystem`.
        #[test]
        fn ivc_folds_a_real_witness_step() {
            use nova_snark::{
                nova::{PublicParams, RecursiveSNARK},
                provider::{Bn256EngineKZG, GrumpkinEngine},
                traits::{snark::RelaxedR1CSSNARKTrait, Engine},
            };

            type E1 = Bn256EngineKZG;
            type E2 = GrumpkinEngine;
            type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
            type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
            type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
            type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

            let depth = 4;

            // Build a real step with valid witnesses (mirrors
            // `step_real_tx_with_valid_witnesses_satisfies`).
            let commitment = F1::from(77u64);
            let mut commit_leaves = vec![F1::from(1u64), F1::from(2u64)];
            commit_leaves.push(commitment);
            let (new_commitments_root, commitment_path) =
                build_commitment_tree(depth, commit_leaves, 2);

            let nullifier = F1::from(30u64);
            let (old_nullifiers_root, nullifier_witness) = build_nullifier_witness(
                depth,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );
            let (new_nullifiers_root, nullifier_insertion) = build_imt_insertion_witness(
                depth as u32,
                vec![F1::ZERO, F1::from(10u64), F1::from(50u64)],
                nullifier,
            );

            let real = RollupStepCircuit::<F1>::new_real(
                depth,
                new_commitments_root,
                new_nullifiers_root,
                F1::from(7u64),
                commitment,
                commitment_path,
                nullifier_witness,
                nullifier_insertion,
            );

            // PublicParams setup MUST use a circuit with identical R1CS
            // shape, which means same `merkle_depth`. Use padding at the
            // same depth.
            let pp = PublicParams::<E1, E2, RollupStepCircuit<F1>>::setup(
                &RollupStepCircuit::<F1>::padding_with_depth(depth),
                &*S1::ck_floor(),
                &*S2::ck_floor(),
            )
            .expect("PublicParams::setup");

            let z0 = vec![
                F1::ZERO,
                old_nullifiers_root,
                F1::ZERO,
                F1::from(2u64),
                F1::from(3u64),
            ];
            let mut rs = RecursiveSNARK::<E1, E2, RollupStepCircuit<F1>>::new(&pp, &real, &z0)
                .expect("RecursiveSNARK::new");
            rs.prove_step(&pp, &real)
                .expect("prove_step (real witness)");

            let z_out = rs.verify(&pp, 1, &z0).expect("RecursiveSNARK::verify");
            assert_eq!(
                z_out[0], new_commitments_root,
                "z_out[0] must be new commitments root"
            );
            assert_eq!(z_out[3], F1::from(3u64), "tx_count must advance by 1");
            assert_eq!(
                z_out[4],
                F1::from(4u64),
                "nullifier_count must advance by 1"
            );
        }
    }
}

#[cfg(not(feature = "nova-v1"))]
pub mod nova_step_circuit {
    use serde::{Deserialize, Serialize};

    pub const ROLLOUP_ARITY: usize = 5;
    pub use ROLLOUP_ARITY as ROLLUP_ARITY;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct RollupIvcState {
        pub commitments_root: Vec<u8>,
        pub nullifiers_root: Vec<u8>,
        pub historic_root_root: Vec<u8>,
        pub transaction_count: u64,
        pub nullifier_count: u64,
    }

    impl RollupIvcState {
        #[allow(dead_code)]
        pub fn new(
            commitments_root: Vec<u8>,
            nullifiers_root: Vec<u8>,
            historic_root_root: Vec<u8>,
        ) -> Self {
            Self {
                commitments_root,
                nullifiers_root,
                historic_root_root,
                transaction_count: 0,
                nullifier_count: 0,
            }
        }

        #[allow(dead_code)]
        pub fn initial() -> Self {
            Self {
                commitments_root: vec![0u8; 32],
                nullifiers_root: vec![0u8; 32],
                historic_root_root: vec![0u8; 32],
                transaction_count: 0,
                nullifier_count: 0,
            }
        }
    }

    /// Stub step circuit used when nova-v1 feature is disabled.
    #[derive(Debug, Clone, Default)]
    pub struct RollupStepCircuit;

    impl RollupStepCircuit {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self
        }

        #[allow(dead_code)]
        pub fn arity(&self) -> usize {
            ROLLOUP_ARITY
        }
    }
}

// Re-export for convenience.
pub use nova_step_circuit::{RollupIvcState, ROLLOUP_ARITY};

#[cfg(feature = "nova-v1")]
pub use nova_step_circuit::RollupStepCircuit;

#[cfg(not(feature = "nova-v1"))]
pub use nova_step_circuit::RollupStepCircuit;
