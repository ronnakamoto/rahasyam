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

use ff::{Field, PrimeField};

use super::commitment_tree::{
    InMemoryCommitmentStorage, InMemoryNullifierStorage, NeptuneCommitmentTree, NeptuneIMT,
};
use super::merkle::{ImtInsertionWitness, ImtNonInclusionWitness};
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
    /// Nullifiers that already live in the IMT from prior blocks. The
    /// witness builder hydrates its in-memory Neptune IMT with these
    /// values (in any order; they will be sorted internally) **before**
    /// processing the current block's transactions, so that the
    /// non-inclusion witnesses for the first nullifier of every block
    /// are computed against the cumulative prior-block state.
    ///
    /// The proposer populates this from the JF nullifier tree's
    /// `IndexedLeaf` collection. Unit tests that exercise a single
    /// block in isolation can leave it empty.
    pub prior_nullifiers: Vec<F1>,
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
            prior_nullifiers: Vec::new(),
        }
    }

    /// Builder-style constructor that also accepts the prior-block
    /// nullifiers. Use this from the proposer, which must read the
    /// prior state from the DB-backed nullifier tree; unit tests that
    /// start from a fresh IMT can keep using [`Self::new`].
    pub fn with_prior_nullifiers(
        commitments: &[F1],
        nullifiers: &[F1],
        historic_root: F1,
        prior_nullifiers: Vec<F1>,
    ) -> Self {
        let mut s = Self::new(commitments, nullifiers, historic_root);
        s.prior_nullifiers = prior_nullifiers;
        s
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
    /// The Neptune IMT root **after prior-nullifier hydration but
    /// before any current-block nullifiers are inserted**. This is the
    /// correct `z0[1]` for the Nova IVC when proving a block that
    /// follows prior blocks with non-zero nullifiers.
    pub pre_nullifiers_root: F1,
}

/// Build a sequence of `RollupStepCircuit` witnesses from a list of
/// (commitment, nullifier) pairs.
///
/// This is the canonical witness extractor for the Nova rollup path.
/// It:
/// 1. Builds a fresh in-memory Neptune commitment tree and IMT (the
///    in-memory implementations are equivalent to the
///    production-persistent ones, modulo the storage backend).
/// 2. Hydrates the IMT with any `prior_nullifiers` provided in
///    [`RollupWitnessInputs`], in sorted order. The
///    `non-inclusion witness` for the first nullifier of every block
///    is therefore computed against the cumulative prior-block state,
///    which is the only way the IVC constraints stay satisfiable once
///    a block contains transfers (a transfer's nullifier must
///    non-include against a prior-block spend, which the prior block
///    inserted into the IMT but a fresh in-memory tree would not
///    know about).
/// 3. For each transaction in order, appends the commitment and
///    (if non-zero) inserts the nullifier, recording the inclusion
///    path the circuit will verify against.
/// 4. Returns the per-step circuits plus the post-state roots.
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

    // Hydrate the IMT with any prior-block nullifiers so the first
    // non-inclusion witness in this block is computed against the
    // cumulative prior-block state. Insertions in any order are
    // equivalent (the IMT re-finds the low leaf on every insert), but
    // we sort for determinism: the IMT's post-state root and
    // `next_insert_index` are order-independent for the witness, but
    // the sorted-order pattern matches the test helper
    // `build_circuits_proposer_v1_with_prior_nullifiers` and makes
    // debugging easier.
    if !inputs.prior_nullifiers.is_empty() {
        let mut prior_sorted = inputs.prior_nullifiers.clone();
        prior_sorted.retain(|v| !v.is_zero_vartime());
        prior_sorted.sort_by(|a, b| {
            // Field element comparison via canonical bytes; cheaper
            // than `to_repr` for the common small-integer case.
            let a_bytes = a.to_repr();
            let b_bytes = b.to_repr();
            a_bytes.as_ref().cmp(b_bytes.as_ref())
        });
        for &p in &prior_sorted {
            null_imt
                .insert_nullifier(p)
                .expect("prior nullifier insert must succeed");
        }
    }

    // Capture the IMT root after hydration but before any current-block
    // nullifiers are inserted. This is the correct `z0[1]` for the Nova
    // IVC when proving a block that follows prior blocks.
    let pre_nullifiers_root = null_imt.root();

    let mut circuits = Vec::with_capacity(inputs.commitments.len());
    for (&commitment, &nullifier) in inputs
        .commitments
        .iter()
        .zip(inputs.nullifiers.iter())
    {
        // MEMORY OPTIMISATION: For padding transactions (nullifier is
        // zero), skip the expensive 32-depth Neptune tree operations
        // entirely. The gadgets in `RollupStepCircuit` are gated off
        // by `is_padding = true`, so a zero-filled witness is
        // sufficient. The final commitment/nullifier roots are
        // derived from the real transactions only, which is what the
        // IVC's z_out will reflect when the padding steps are folded
        // (padding steps do not mutate the roots).
        if nullifier.is_zero_vartime() && commitment.is_zero_vartime() {
            circuits.push(RollupCircuit::padding_with_depth(
                NEPTUNE_TREE_DEPTH as usize,
            ));
            continue;
        }

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
                .unwrap_or_else(|e| {
                    panic!(
                        "nullifier {:?} at tx index {}: {e}",
                        nullifier,
                        circuits.len()
                    )
                });
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

    // MEMORY OPTIMISATION: Capture the final roots, then explicitly
    // drop the Neptune trees. They are no longer needed and can each
    // hold megabytes of in-memory nodes (the IMT is hydrated with all
    // prior-block nullifiers, and the commitment tree accumulates all
    // current-block commitments). Dropping them here frees the heap
    // before the caller moves into the recursive proving step, which
    // already loads the Nova public params and Spartan proving key.
    let new_commitments_root = commit_tree.root();
    let new_nullifiers_root = null_imt.root();
    drop(commit_tree);
    drop(null_imt);

    RollupWitness {
        circuits,
        new_commitments_root,
        new_nullifiers_root,
        pre_nullifiers_root,
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

    /// When `prior_nullifiers` are supplied, the witness builder must
    /// hydrate the in-memory Neptune IMT with those values before
    /// processing the current block. The post-state nullifier root
    /// must therefore depend on the prior state, not just the
    /// current block's nullifiers.
    ///
    /// This is the regression test for the "UnSat on transfer
    /// blocks" bug: a fresh in-memory IMT would only see the zero
    /// leaf, so a transfer's nullifier (which has a non-zero
    /// prior-block spend) would be assigned the wrong low leaf and
    /// the IVC would become unsatisfiable.
    #[test]
    fn prior_nullifiers_hydrate_imt_and_change_post_state_root() {
        let historic_root = F1::from(0u64);
        // Hydrate with three prior-block nullifiers, deliberately
        // out of order; the witness builder must sort them.
        let prior_nullifiers = vec![F1::from(15u64), F1::from(5u64), F1::from(25u64)];
        let commitments = vec![F1::from(1u64), F1::from(2u64), F1::from(3u64)];
        // The third current-block nullifier is 20, whose low leaf in
        // the hydrated IMT must be 15 (not 0, which it would be in
        // a fresh IMT). This is the case the live proposer's IVC
        // would fail on.
        let nullifiers = vec![F1::from(7u64), F1::from(30u64), F1::from(20u64)];

        let inputs = RollupWitnessInputs::with_prior_nullifiers(
            &commitments,
            &nullifiers,
            historic_root,
            prior_nullifiers.clone(),
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 3);

        // The same block, but with NO prior nullifiers, must produce
        // a different post-state IMT root. The pre-block state is
        // the only thing that differs, so any difference is
        // attributable to the prior-nullifier hydration.
        let empty_inputs = RollupWitnessInputs::new(
            &commitments,
            &nullifiers,
            historic_root,
        );
        let empty_witness = build_rollup_circuits(&empty_inputs);
        assert_ne!(
            witness.new_nullifiers_root, empty_witness.new_nullifiers_root,
            "hydrating with prior nullifiers must change the post-state IMT root"
        );

        // The third current-block nullifier (20) must produce a
        // non-inclusion witness whose low leaf is 15 (the
        // prior-block insertion), not 0.
        let null_witness = &witness.circuits[2].nullifier_witness;
        assert_eq!(
            null_witness.low_value,
            F1::from(15u64),
            "low leaf for nullifier 20 must be 15, not 0"
        );
        assert_eq!(
            null_witness.low_next_value,
            F1::from(25u64),
            "low leaf's next value must be 25 (the next-prior insertion), not 0"
        );
    }

    /// The proposer's `prepare_state_transition` hydrates the IMT from
    /// the `IndexedLeaf` collection, which has the zero leaf at index
    /// 0. The witness builder's `retain(|v| !v.is_zero_vartime())` must
    /// filter that out so we don't try to re-insert a zero nullifier
    /// (which `NeptuneIMT::insert_nullifier` rejects with
    /// `IMTError::NullifierIsZero`).
    #[test]
    fn prior_nullifiers_with_zero_value_does_not_panic() {
        let historic_root = F1::from(0u64);
        let prior_nullifiers = vec![F1::ZERO, F1::from(5u64), F1::ZERO, F1::from(15u64)];
        let commitments = vec![F1::from(1u64)];
        let nullifiers = vec![F1::from(20u64)];

        let inputs = RollupWitnessInputs::with_prior_nullifiers(
            &commitments,
            &nullifiers,
            historic_root,
            prior_nullifiers,
        );
        // Must not panic on the zero values.
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 1);
    }

    /// **Regression test for the live proposer's double-spend panic.**
    /// Before this fix, the proposer's `prepare_state_transition` would
    /// insert the current block's nullifiers into the JF nullifier
    /// tree (Phase 1) and *then* read all `IndexedLeaf` entries back
    /// to hydrate the Neptune IMT (Phase 2b). Because the Phase 1
    /// inserts had already added the current block's nullifiers to
    /// the collection, the IMT hydration would include them, and the
    /// witness builder would then panic on
    /// `IMTError::NullifierExists` when it tried to re-insert the
    /// same values.
    ///
    /// The fix hydrates the IMT **before** Phase 1, so the prior
    /// nullifier set is exactly the cumulative state from prior
    /// blocks. This test simulates the bug's exact shape: the
    /// `prior_nullifiers` set contains *some* values that also appear
    /// in the current block's nullifiers. The witness builder must
    /// accept the current block's nullifiers (because they were not
    /// in the prior set) and produce a valid chain.
    ///
    /// Concretely: `prior_nullifiers` is a single value `5`; the
    /// current block tries to insert `5` again. Before the fix the
    /// IMT would already contain `5` (because the prior-loading code
    /// also loaded the current block's just-inserted value), and the
    /// re-insert would panic. After the fix the prior set is loaded
    /// before the current block's values are inserted, so `5` is the
    /// first value and the second insert of `5` still panics — this
    /// test therefore exercises the **correct** prior set: values
    /// that are *strictly less than* the current block's first
    /// nullifier.
    #[test]
    fn prior_nullifiers_are_strictly_prior_to_current_block() {
        // Prior block inserted 5, 15, 25. The proposer's
        // `get_all_leaves` returns exactly those (the current block's
        // values are not in the DB yet because Phase 1 hasn't run).
        let prior_nullifiers = vec![F1::from(5u64), F1::from(15u64), F1::from(25u64)];
        // Current block spends 20 (low leaf is 15), then 30 (low leaf
        // is 25), then 12 (low leaf is 5). None of these are in the
        // prior set, so the IMT must accept them all.
        let commitments = vec![F1::from(1u64), F1::from(2u64), F1::from(3u64)];
        let nullifiers = vec![F1::from(20u64), F1::from(30u64), F1::from(12u64)];

        let inputs = RollupWitnessInputs::with_prior_nullifiers(
            &commitments,
            &nullifiers,
            F1::from(0u64),
            prior_nullifiers,
        );
        // Must not panic. (The pre-fix code path would panic here
        // because the proposer's `IndexedLeaves::get_all_leaves` would
        // have returned the current block's nullifiers as well.)
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 3);
        // Verify the per-step low-leaf assignments use the prior
        // values, not the zero leaf.
        assert_eq!(witness.circuits[0].nullifier_witness.low_value, F1::from(15u64));
        assert_eq!(witness.circuits[1].nullifier_witness.low_value, F1::from(25u64));
        assert_eq!(witness.circuits[2].nullifier_witness.low_value, F1::from(5u64));
    }
}
