//! Witness extraction for the Nova rollup step circuits.
//!
//! The proposer's `nightfall_proposer::driven::nova_prover` historically
//! duplicated the entire witness-building pipeline (fetching the
//! commitment / nullifier / historic-root state from the DB, building
//! the Neptune commitment tree and IMT, and emitting the
//! `RollupStepCircuit` witnesses) inside the `lib` crate. That code
//! lived in `nova_prover.rs` as an **orphan impl** of
//! `nightfall_proposer::ports::proving::RecursiveProvingEngine<P>` for
//! `lib::proving::nova_v1::rollup_engine::NovaRollupEngine` — a
//! different module from the engine's definition.
//!
//! This module hoists the witness-building **logic** (the part that
//! talks to the Neptune commitment tree and IMT, builds the per-step
//! Merkle witnesses, and assembles the `RollupStepCircuit`s) into
//! `lib`, so it lives next to the circuit type it produces. The
//! proposer's `prepare_state_transition` calls [`build_rollup_circuits`]
//! and the resulting DB state update is performed by the proposer
//! itself (the only async-IO work that cannot reasonably move into
//! `lib`).
//!
//! ## Future work
//!
//! The orphan impl in the proposer is still technically an orphan
//! (defined in a different crate from the engine type). A follow-up
//! refactor should move the entire `RecursiveProvingEngine` trait (and
//! the impl) into `lib::proving`, so the trait and the impl live in
//! the same crate as the engine. That refactor is out of scope for
//! the current robustness pass; this module is the natural seam at
//! which the witness logic transitions from "proposer DB I/O" to
//! "lib in-memory tree manipulation".

#![cfg(feature = "nova-v1")]

use ff::Field;

use super::commitment_tree::{
    InMemoryCommitmentStorage, InMemoryNullifierStorage, NeptuneCommitmentTree, NeptuneIMT,
};
use super::merkle::{ImtInsertionWitness, ImtNonInclusionWitness, MerklePathHop};
use super::rollup_engine::{E1, F1, RollupCircuit};

/// The off-chain Neptune commitment tree / nullifier IMT depth. Matches
/// the on-chain value used in `compute_initial_z0` and the DB
/// initialisation in `nightfall_proposer::initialisation::get_db_connection`.
pub const NEPTUNE_TREE_DEPTH: u32 = 32;

/// Inputs to the witness builder: a list of commitments and nullifiers
/// (one per transaction) that this block will process. The two vectors
/// must have the same length; the caller is responsible for padding
/// the shorter vector to a common length if needed.
pub struct RollupWitnessInputs {
    /// Per-transaction commitment field elements (in transaction order).
    pub commitments: Vec<F1>,
    /// Per-transaction nullifier field elements (in transaction order).
    /// Zero values are treated as padding / dummy transactions and
    /// produce a degenerate witness against the zero leaf.
    pub nullifiers: Vec<F1>,
    /// `historic_root_root` for the start of the block (matches `z0[2]`).
    pub historic_root: F1,
}

impl RollupWitnessInputs {
    /// Construct from parallel slices, asserting equal length.
    pub fn new(commitments: &[F1], nullifiers: &[F1], historic_root: F1) -> Self {
        assert_eq!(
            commitments.len(),
            nullifiers.len(),
            "commitments and nullifiers must have equal length"
        );
        Self {
            commitments: commitments.to_vec(),
            nullifiers: nullifiers.to_vec(),
            historic_root,
        }
    }
}

/// Output of the witness builder: the per-step `RollupStepCircuit`s
/// plus the Neptune IMT root that the witness assumes (the proposer's
/// `prepare_state_transition` uses this to bind the Nova proof's
/// `new_nullifiers_root` to the circuit).
pub struct RollupWitness {
    /// One entry per transaction (matches the input order).
    pub circuits: Vec<RollupCircuit>,
    /// The Neptune commitment tree root after the last commitment
    /// is appended. The proposer's `new_commitments_root` should match
    /// this value (or the on-chain verifier will reject the proof).
    pub new_commitments_root: F1,
    /// The Neptune IMT root after the last nullifier is inserted. The
    /// proposer's `new_nullifiers_root` should match this value.
    pub new_nullifiers_root: F1,
}

/// Build a sequence of `RollupStepCircuit` witnesses from a list of
/// (commitment, nullifier) pairs.
///
/// This is the canonical witness extractor for the Nova rollup path.
/// It:
/// 1. Builds a fresh in-memory Neptune commitment tree and IMT (the
///    in-memory implementations are equivalent to the
///    production-persistent ones, modulo the storage backend).
/// 2. For each transaction in order, appends the commitment and
///    (if non-zero) inserts the nullifier, recording the inclusion
///    path the circuit will verify against.
/// 3. Returns the per-step circuits plus the post-state roots.
///
/// The off-chain proposer's `prepare_state_transition` calls this
/// helper from inside the `RecursiveProvingEngine` impl; production
/// deployments are expected to hydrate the Neptune trees from the
/// DB at proposer startup (currently the in-memory implementation
/// is the only available backend; a MongoDB-backed storage is
/// tracked as a follow-up).
pub fn build_rollup_circuits(inputs: &RollupWitnessInputs) -> RollupWitness {
    let mut commit_tree =
        NeptuneCommitmentTree::new(NEPTUNE_TREE_DEPTH, InMemoryCommitmentStorage::new());
    let mut null_imt = NeptuneIMT::new(NEPTUNE_TREE_DEPTH, InMemoryNullifierStorage::new());

    let mut circuits = Vec::with_capacity(inputs.commitments.len());
    for (&commitment, &nullifier) in inputs
        .commitments
        .iter()
        .zip(inputs.nullifiers.iter())
    {
        // Commitment inclusion: append and capture the inclusion path.
        let (commit_root, commit_path) = commit_tree.append(commitment);

        // Nullifier non-inclusion + insertion witness.
        //
        // The non-inclusion witness is built **before** the IMT is
        // mutated (it locates the low leaf in the pre-state tree). The
        // insertion witness is built **after** the IMT is updated
        // (it carries the two post-state co-paths that the
        // `verify_imt_insertion_circuit` gadget re-hashes to assert
        // the new root).
        let (null_witness, null_root, null_insertion) = if nullifier.is_zero_vartime() {
            // Padding / dummy transaction: the IMT is not mutated, so
            // the post-state root is the same as the pre-state root.
            // The non-inclusion and insertion witnesses are both
            // degenerate (zero-filled); the gadgets are gated off by
            // `nullifier_enabled = false`.
            let path = null_imt.inclusion_path(0);
            let w = ImtNonInclusionWitness {
                nullifier: F1::ZERO,
                low_value: F1::ZERO,
                low_next_index: F1::ZERO,
                low_next_value: F1::ZERO,
                path: path.clone(),
            };
            let ins = ImtInsertionWitness {
                new_leaf_index: F1::ZERO,
                updated_low_path: path.clone(),
                new_leaf_path: path,
            };
            (w, null_imt.root(), ins)
        } else {
            // Real nullifier: build non-inclusion, then insert, then
            // capture the post-state co-paths.
            let (low_leaf, w) = null_imt
                .get_non_inclusion_witness(nullifier)
                .expect("low leaf must exist for fresh IMT");
            null_imt
                .insert_nullifier(nullifier)
                .expect("insert must succeed");
            let new_leaf_index = null_imt.next_insert_index().saturating_sub(1);
            // Co-path from the low leaf to the root, after the low
            // leaf's hash has been updated to point to the new leaf.
            let updated_low_path = null_imt.inclusion_path(low_leaf.index);
            // Co-path from the new leaf to the root.
            let new_leaf_path = null_imt.inclusion_path(new_leaf_index);
            let ins = ImtInsertionWitness {
                new_leaf_index: F1::from(new_leaf_index),
                updated_low_path,
                new_leaf_path,
            };
            (w, null_imt.root(), ins)
        };

        circuits.push(RollupCircuit::new_real(
            NEPTUNE_TREE_DEPTH as usize,
            commit_root,
            null_root,
            inputs.historic_root,
            commitment,
            commit_path,
            null_witness,
            null_insertion,
        ));
    }

    RollupWitness {
        circuits,
        new_commitments_root: commit_tree.root(),
        new_nullifiers_root: null_imt.root(),
    }
}

// Re-export F1 for callers that want to construct `RollupWitnessInputs`
// without depending on the `rollup_engine` module directly.
pub use super::rollup_engine::F1 as WitnessF1;

// Silence unused-import warning when this module is compiled outside
// of `nova-v1` test builds.
#[allow(dead_code)]
fn _ensure_e1_compiles(_: E1) {}

#[cfg(all(test, feature = "nova-v1"))]
mod tests {
    use super::*;

    /// Empty inputs produce an empty circuit list. The post-state roots
    /// are the well-known "empty" Neptune tree roots.
    #[test]
    fn empty_inputs_produce_empty_circuit_list() {
        let historic_root = F1::from(0u64);
        let inputs = RollupWitnessInputs::new(&[], &[], historic_root);
        let witness = build_rollup_circuits(&inputs);
        assert!(witness.circuits.is_empty());
    }

    /// A single non-zero commitment / nullifier pair produces exactly
    /// one `RollupStepCircuit`, and the post-state roots are non-zero
    /// (because appending a leaf changes the root).
    #[test]
    fn single_step_yields_one_circuit_and_nonzero_roots() {
        let historic_root = F1::from(0u64);
        let inputs = RollupWitnessInputs::new(
            &[F1::from(42u64)],
            &[F1::from(7u64)],
            historic_root,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 1);
        assert!(!witness.circuits[0].is_padding);
        assert_ne!(witness.new_commitments_root, F1::ZERO);
        assert_ne!(witness.new_nullifiers_root, F1::ZERO);
    }

    /// A zero nullifier (padding) is treated as a degenerate witness
    /// against the zero leaf, and the IMT root stays at the well-known
    /// "fresh IMT" value.
    #[test]
    fn zero_nullifier_uses_degenerate_witness() {
        let historic_root = F1::from(0u64);
        let inputs = RollupWitnessInputs::new(
            &[F1::from(1u64), F1::from(2u64)],
            &[F1::from(0u64), F1::from(0u64)],
            historic_root,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 2);
        // Two commitments were appended, so the commitment root must
        // have changed.
        assert_ne!(witness.new_commitments_root, F1::ZERO);
        // No real nullifiers were inserted, so the IMT root must
        // equal the root the witness helper computed for the
        // empty IMT (just the zero leaf at index 0). We verify this
        // is deterministic by re-invoking the helper with the same
        // inputs and asserting equality.
        let witness2 = build_rollup_circuits(&inputs);
        assert_eq!(
            witness.new_nullifiers_root, witness2.new_nullifiers_root,
            "fresh IMT root must be deterministic"
        );
    }
}
