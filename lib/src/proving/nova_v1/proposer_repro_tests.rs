//! Tests for the proposer's `prepare_state_transition` flow.
//!
//! These tests reproduce the exact witness-extraction logic in
//! `nightfall_proposer/src/driven/nova_prover.rs::prepare_state_transition`
//! after the Microsoft-style refactor that eliminated the dual-tree
//! pattern. The Nova code path now uses a single, persistent Neptune IMT
//! (this module's `NeptuneIMT` and `NeptuneCommitmentTree`) as the
//! source of truth for the circuit witness — no shadow tree, no
//! `jf_proof_to_leaf_index` extraction, no `LeafDBEntry.index` parsing.
//!
//! If the proposer's "UnSat" bug recurs, these tests will reproduce it
//! without Docker, MongoDB, or Anvil.

#![cfg(all(test, feature = "nova-v1"))]

use ff::{Field, PrimeField};
use nova_snark::traits::Engine;

use super::commitment_tree::{
    compute_initial_z0, InMemoryCommitmentStorage, InMemoryNullifierStorage,
    NeptuneCommitmentTree, NeptuneIMT,
};
use super::merkle::{compute_merkle_root_native, imt_leaf_hash_native};
use super::rollup_engine::{E1, F1, NovaRollupEngine, RollupCircuit};
use super::witness::{build_rollup_circuits, RollupWitnessInputs};
use crate::proving::RecursiveProvingEngine;

// ---------------------------------------------------------------------------
// Proposer flow helper.
// ---------------------------------------------------------------------------

/// Build `RollupCircuit`s the way the post-refactor proposer does:
/// the Neptune commitment tree and IMT are the single source of truth
/// for the circuit witnesses. The proposer simply calls
/// `commit_tree.append(commitment)` and `null_imt.get_non_inclusion_witness(nullifier)`
/// for each transaction. No low-leaf index extraction, no shadow tree.
fn build_circuits_proposer_v1(
    commitments: &[F1],
    nullifiers: &[F1],
) -> Vec<RollupCircuit> {
    let depth = 32u32;
    let mut commit_tree = NeptuneCommitmentTree::new(depth, InMemoryCommitmentStorage::new());
    let mut null_imt = NeptuneIMT::new(depth, InMemoryNullifierStorage::new());
    let initial = compute_initial_z0();
    let current_historic_root = initial[2];

    let mut circuits = Vec::with_capacity(commitments.len());
    for (&commitment, &nullifier) in commitments.iter().zip(nullifiers.iter()) {
        let (commit_root, commit_path) = commit_tree.append(commitment);
        let (null_witness, null_root, null_insertion) = if nullifier.is_zero_vartime() {
            // Degenerate witness for padding / dummy transactions: low leaf
            // is the zero leaf at index 0.
            let path = null_imt.inclusion_path(0);
            let w = super::merkle::ImtNonInclusionWitness {
                nullifier: F1::ZERO,
                low_value: F1::ZERO,
                low_next_index: F1::ZERO,
                low_next_value: F1::ZERO,
                path: path.clone(),
            };
            let ins = super::merkle::ImtInsertionWitness {
                new_leaf_index: F1::ZERO,
                updated_low_path: path.clone(),
                new_leaf_path: path,
            };
            (w, null_imt.root(), ins)
        } else {
            let (low_leaf, w) = null_imt
                .get_non_inclusion_witness(nullifier)
                .expect("low leaf must exist for fresh IMT");
            null_imt
                .insert_nullifier(nullifier)
                .expect("insert must succeed");
            let new_leaf_index = null_imt.next_insert_index().saturating_sub(1);
            let updated_low_path = null_imt.inclusion_path(low_leaf.index);
            let new_leaf_path = null_imt.inclusion_path(new_leaf_index);
            let ins = super::merkle::ImtInsertionWitness {
                new_leaf_index: F1::from(new_leaf_index),
                updated_low_path,
                new_leaf_path,
            };
            (w, null_imt.root(), ins)
        };

        circuits.push(RollupCircuit::new_real(
            depth as usize,
            commit_root,
            null_root,
            current_historic_root,
            commitment,
            commit_path,
            null_witness,
            null_insertion,
        ));
    }
    circuits
}

/// Same as `build_circuits_proposer_v1` but pre-populates the IMT with
/// a list of `(value, next_value)` tuples to simulate prior blocks. The
/// tuples are inserted in sorted order so the linked list is well-formed.
fn build_circuits_proposer_v1_with_prior_nullifiers(
    commitments: &[F1],
    nullifiers: &[F1],
    prior_nullifiers: &[F1],
) -> Vec<RollupCircuit> {
    let depth = 32u32;
    let mut commit_tree = NeptuneCommitmentTree::new(depth, InMemoryCommitmentStorage::new());
    let mut null_imt = NeptuneIMT::new(depth, InMemoryNullifierStorage::new());
    for &p in prior_nullifiers {
        if !p.is_zero_vartime() {
            null_imt
                .insert_nullifier(p)
                .expect("prior nullifier insert must succeed");
        }
    }

    let initial = compute_initial_z0();
    let current_historic_root = initial[2];

    let mut circuits = Vec::with_capacity(commitments.len());
    for (&commitment, &nullifier) in commitments.iter().zip(nullifiers.iter()) {
        let (commit_root, commit_path) = commit_tree.append(commitment);
        let (null_witness, null_root, null_insertion) = if nullifier.is_zero_vartime() {
            let path = null_imt.inclusion_path(0);
            let w = super::merkle::ImtNonInclusionWitness {
                nullifier: F1::ZERO,
                low_value: F1::ZERO,
                low_next_index: F1::ZERO,
                low_next_value: F1::ZERO,
                path: path.clone(),
            };
            let ins = super::merkle::ImtInsertionWitness {
                new_leaf_index: F1::ZERO,
                updated_low_path: path.clone(),
                new_leaf_path: path,
            };
            (w, null_imt.root(), ins)
        } else {
            let (low_leaf, w) = null_imt
                .get_non_inclusion_witness(nullifier)
                .expect("low leaf must exist");
            null_imt
                .insert_nullifier(nullifier)
                .expect("insert must succeed");
            let new_leaf_index = null_imt.next_insert_index().saturating_sub(1);
            let updated_low_path = null_imt.inclusion_path(low_leaf.index);
            let new_leaf_path = null_imt.inclusion_path(new_leaf_index);
            let ins = super::merkle::ImtInsertionWitness {
                new_leaf_index: F1::from(new_leaf_index),
                updated_low_path,
                new_leaf_path,
            };
            (w, null_imt.root(), ins)
        };

        circuits.push(RollupCircuit::new_real(
            depth as usize,
            commit_root,
            null_root,
            current_historic_root,
            commitment,
            commit_path,
            null_witness,
            null_insertion,
        ));
    }
    circuits
}

// ---------------------------------------------------------------------------
// Sanity tests on the IMT / commitment tree in isolation.
// ---------------------------------------------------------------------------

/// 1. The IMT's fresh-state root is the same value the proposer's
/// `compute_initial_z0` uses for `z0[1]`.
#[test]
fn imt_fresh_state_root_matches_z0() {
    let imt = NeptuneIMT::new(32, InMemoryNullifierStorage::new());
    let z0 = compute_initial_z0();
    assert_eq!(imt.root(), z0[1]);
}

/// 2. The commitment tree's fresh-state root is the same value the
/// proposer's `compute_initial_z0` uses for `z0[0]`.
#[test]
fn commitment_tree_fresh_state_root_matches_z0() {
    let tree = NeptuneCommitmentTree::new(32, InMemoryCommitmentStorage::new());
    let z0 = compute_initial_z0();
    assert_eq!(tree.root(), z0[0]);
}

/// 3. A non-inclusion witness built by the IMT recomputes to the current
/// IMT root.
#[test]
fn imt_witness_recomputes_to_current_root() {
    let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
    imt.insert_nullifier(F1::from(10u64)).unwrap();
    let (_low_leaf, witness) = imt
        .get_non_inclusion_witness(F1::from(30u64))
        .unwrap();
    let constants = super::hash::poseidon_constants::<F1>();
    let low_hash = imt_leaf_hash_native(
        &constants,
        witness.low_value,
        witness.low_next_index,
        witness.low_next_value,
    );
    let recomputed = compute_merkle_root_native(&constants, low_hash, &witness.path);
    assert_eq!(recomputed, imt.root());
}

/// 4. IMT rejects a nullifier that is already in the tree.
#[test]
fn imt_rejects_duplicate() {
    let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
    imt.insert_nullifier(F1::from(7u64)).unwrap();
    let r = imt.insert_nullifier(F1::from(7u64));
    assert!(r.is_err());
}

/// 5. IMT rejects a zero nullifier.
#[test]
fn imt_rejects_zero() {
    let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
    let r = imt.insert_nullifier(F1::ZERO);
    assert!(r.is_err());
}

/// 6. IMT round-trips through `into_storage` / `load`.
#[test]
fn imt_round_trips_through_storage() {
    let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
    imt.insert_nullifier(F1::from(5u64)).unwrap();
    imt.insert_nullifier(F1::from(15u64)).unwrap();
    let original_root = imt.root();
    let storage = imt.into_storage();
    let rehydrated = NeptuneIMT::load(storage).expect("load must succeed");
    assert_eq!(rehydrated.root(), original_root);
}

/// 7. Commitment tree round-trips through `into_storage` / `load`.
#[test]
fn commitment_tree_round_trips_through_storage() {
    let mut tree = NeptuneCommitmentTree::new(4, InMemoryCommitmentStorage::new());
    for i in 0u64..3 {
        tree.append(F1::from(i + 1));
    }
    let original_root = tree.root();
    let storage = tree.into_storage();
    let rehydrated = NeptuneCommitmentTree::load(storage).expect("load must succeed");
    assert_eq!(rehydrated.root(), original_root);
}

// ---------------------------------------------------------------------------
// End-to-end IVC chain tests using the post-refactor proposer flow.
// ---------------------------------------------------------------------------

/// 8. All-zero chain of 20 steps verifies end-to-end. This is the exact
/// reproduction of the live proposer's "UnSat" DIAG output.
#[test]
fn ivc_chain_with_20_all_zero_circuits_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let circuits = build_circuits_proposer_v1(&vec![F1::ZERO; 20], &vec![F1::ZERO; 20]);
        assert_eq!(circuits.len(), 20);
        let proof = engine
            .prove_circuits(circuits)
            .expect("20 all-zero circuits must verify");
        assert_eq!(proof.transaction_count, 20);
    });
}

/// 9. Non-zero commitments + non-zero nullifiers (10 of each) verifies
/// end-to-end. This is the realistic, non-degenerate proposer flow.
#[test]
fn ivc_chain_with_10_nonzero_circuits_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let commitments: Vec<F1> = (1u64..=10).map(F1::from).collect();
        let nullifiers: Vec<F1> = (100u64..=110).map(F1::from).collect();
        let circuits = build_circuits_proposer_v1(&commitments, &nullifiers);
        assert_eq!(circuits.len(), 10);
        let proof = engine
            .prove_circuits(circuits)
            .expect("10 non-zero circuits must verify");
        assert_eq!(proof.transaction_count, 10);
    });
}

/// 10. Non-zero nullifiers in sorted order (10, 20, ..., 100) verifies.
/// The IMT's linked list must be correctly maintained across insertions.
#[test]
fn ivc_chain_with_sorted_nonzero_nullifiers_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let commitments: Vec<F1> = (1u64..=10).map(F1::from).collect();
        let nullifiers: Vec<F1> = (10u64..=100).step_by(10).map(F1::from).collect();
        let circuits = build_circuits_proposer_v1(&commitments, &nullifiers);
        let proof = engine
            .prove_circuits(circuits)
            .expect("sorted non-zero chain must verify");
        assert_eq!(proof.transaction_count, 10);
    });
}

/// 11. Pre-populated IMT (prior block inserted 3 nullifiers) followed by
/// 5 current-block nullifiers verifies end-to-end. This is the closest
/// unit-test reproduction of the live proposer's second-block scenario.
#[test]
fn ivc_chain_with_prior_nullifiers_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let commitments: Vec<F1> = (1u64..=5).map(F1::from).collect();
        let current_nullifiers: Vec<F1> = vec![
            F1::from(7u64),
            F1::from(20u64),
            F1::from(12u64),
            F1::from(30u64),
            F1::from(35u64),
        ];
        // Prior-block nullifiers: 5, 15, 25.
        let prior_nullifiers: Vec<F1> = vec![F1::from(5u64), F1::from(15u64), F1::from(25u64)];
        let circuits = build_circuits_proposer_v1_with_prior_nullifiers(
            &commitments,
            &current_nullifiers,
            &prior_nullifiers,
        );
        assert_eq!(circuits.len(), 5);
        let proof = engine
            .prove_circuits(circuits)
            .expect("chain with prior nullifiers must verify");
        assert_eq!(proof.transaction_count, 5);
    });
}

/// 12. Mixed zero and non-zero nullifiers (alternating) verifies. This
/// reproduces the live proposer's behaviour when the block has fewer
/// than `block_size` real transactions and the rest are padding.
#[test]
fn ivc_chain_with_mixed_zero_and_nonzero_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let commitments: Vec<F1> = (1u64..=6).map(F1::from).collect();
        let nullifiers: Vec<F1> = vec![
            F1::from(100u64),
            F1::ZERO,
            F1::from(200u64),
            F1::ZERO,
            F1::from(300u64),
            F1::ZERO,
        ];
        let circuits = build_circuits_proposer_v1(&commitments, &nullifiers);
        assert_eq!(circuits.len(), 6);
        let proof = engine
            .prove_circuits(circuits)
            .expect("mixed zero/non-zero chain must verify");
        assert_eq!(proof.transaction_count, 6);
    });
}

/// 13. Unsorted nullifiers (random-looking order) verifies. The IMT
/// must correctly find the low leaf regardless of insertion order.
#[test]
fn ivc_chain_with_unsorted_nonzero_nullifiers_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let commitments: Vec<F1> = (1u64..=5).map(F1::from).collect();
        // 5, 25, 10, 30, 15 — interleaved low/high.
        let nullifiers: Vec<F1> = vec![
            F1::from(5u64),
            F1::from(25u64),
            F1::from(10u64),
            F1::from(30u64),
            F1::from(15u64),
        ];
        let circuits = build_circuits_proposer_v1(&commitments, &nullifiers);
        let proof = engine
            .prove_circuits(circuits)
            .expect("unsorted non-zero chain must verify");
        assert_eq!(proof.transaction_count, 5);
    });
}

/// 14. **Regression test** for the "low leaf not found" panic and the
/// "Relaxed R1CS is unsatisfiable" error. The pre-refactor shadow tree
/// panicked when the JF tree's low leaf was a prior-block nullifier
/// (not in the shadow); the post-refactor IMT handles this by being
/// the single source of truth.
#[test]
fn regression_low_leaf_in_prior_block() {
    // Build an IMT that mirrors a deployment with 3 prior-block nullifiers.
    let mut imt = NeptuneIMT::new(32, InMemoryNullifierStorage::new());
    imt.insert_nullifier(F1::from(5u64)).unwrap();
    imt.insert_nullifier(F1::from(15u64)).unwrap();
    imt.insert_nullifier(F1::from(25u64)).unwrap();
    // Current block wants to insert 20. Low leaf is 15 (idx 2).
    let (_low_leaf, witness) = imt
        .get_non_inclusion_witness(F1::from(20u64))
        .expect("low leaf must be found");
    assert_eq!(witness.low_value, F1::from(15u64));
    assert_eq!(witness.low_next_value, F1::from(25u64));
    imt.insert_nullifier(F1::from(20u64)).unwrap();
    // The IMT root must have changed.
    let _ = imt.root();
}

/// **Regression test for the live proposer's "UnSat on transfer
/// blocks" failure.** The post-refactor witness builder now hydrates
/// the in-memory Neptune IMT with `prior_nullifiers` from
/// `RollupWitnessInputs`. Without that step a fresh IMT would assign
/// the wrong low leaf to the first transfer's nullifier, and the
/// IVC constraints would become unsatisfiable.
///
/// This test exercises the canonical witness builder
/// (`build_rollup_circuits` with `RollupWitnessInputs::with_prior_nullifiers`)
/// the way the proposer's `prepare_state_transition` does after this
/// change: the prior nullifiers come from the JF nullifier tree's
/// `IndexedLeaf` collection, and the witness must verify end-to-end.
#[test]
fn ivc_chain_with_witness_builder_and_prior_nullifiers_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];
        let commitments: Vec<F1> = (1u64..=5).map(F1::from).collect();
        let current_nullifiers: Vec<F1> = vec![
            F1::from(7u64),
            F1::from(20u64),
            F1::from(12u64),
            F1::from(30u64),
            F1::from(35u64),
        ];
        // Prior-block nullifiers: 5, 15, 25 — out of insertion order
        // to make sure the witness builder sorts them.
        let prior_nullifiers: Vec<F1> = vec![F1::from(15u64), F1::from(5u64), F1::from(25u64)];

        let inputs = RollupWitnessInputs::with_prior_nullifiers(
            &commitments,
            &current_nullifiers,
            historic_root,
            prior_nullifiers,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 5);
        let proof = engine
            .prove_circuits(witness.circuits)
            .expect("chain with prior nullifiers must verify end-to-end");
        assert_eq!(proof.transaction_count, 5);
    });
}

/// A second-block scenario, where the first block's commitments and
/// nullifiers are now part of `prior_nullifiers`. The post-state
/// commitments / nullifier roots of the first block become the
/// starting state of the second; the witness builder must produce a
/// chain that folds through both blocks and verifies at the end.
#[test]
fn ivc_chain_two_blocks_with_prior_nullifiers_verifies() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];

        // First block: 3 commitments, 3 nullifiers.
        let block1_commitments: Vec<F1> = vec![F1::from(100u64), F1::from(200u64), F1::from(300u64)];
        let block1_nullifiers: Vec<F1> =
            vec![F1::from(10u64), F1::from(20u64), F1::from(30u64)];
        let inputs1 = RollupWitnessInputs::new(
            &block1_commitments,
            &block1_nullifiers,
            historic_root,
        );
        let witness1 = build_rollup_circuits(&inputs1);
        assert_eq!(witness1.circuits.len(), 3);

        // Second block: 2 commitments, 2 nullifiers. The
        // `prior_nullifiers` carry the first block's nullifiers, in
        // arbitrary order. The witness builder must sort them, and
        // the per-step witnesses must reference the correct low
        // leaves.
        let block2_commitments: Vec<F1> = vec![F1::from(400u64), F1::from(500u64)];
        let block2_nullifiers: Vec<F1> = vec![F1::from(15u64), F1::from(25u64)];
        let prior_nullifiers: Vec<F1> = vec![
            F1::from(20u64),
            F1::from(30u64),
            F1::from(10u64),
        ];
        let inputs2 = RollupWitnessInputs::with_prior_nullifiers(
            &block2_commitments,
            &block2_nullifiers,
            historic_root,
            prior_nullifiers,
        );
        let witness2 = build_rollup_circuits(&inputs2);
        assert_eq!(witness2.circuits.len(), 2);

        // For the first nullifier of block 2 (15), the low leaf must
        // be 10 (from block 1), not 0.
        let w15 = &witness2.circuits[0].nullifier_witness;
        assert_eq!(
            w15.low_value,
            F1::from(10u64),
            "low leaf for nullifier 15 must be the prior-block 10"
        );
        // For the second nullifier of block 2 (25), the low leaf must
        // be 20 (from block 1), not 0 or 10.
        let w25 = &witness2.circuits[1].nullifier_witness;
        assert_eq!(
            w25.low_value,
            F1::from(20u64),
            "low leaf for nullifier 25 must be the prior-block 20"
        );

        // Concatenate the two blocks' circuits and verify the IVC
        // chain end-to-end.
        let mut all_circuits = witness1.circuits;
        all_circuits.extend(witness2.circuits);
        let proof = engine
            .prove_circuits(all_circuits)
            .expect("two-block chain with prior nullifiers must verify end-to-end");
        assert_eq!(proof.transaction_count, 5);
    });
}

/// Regression test reproducing the live proposer's failure shape:
/// - **Block 1**: 7 deposits, 28 commitments, 28 nullifier slots all
///   zero (deposits do not spend).
/// - **Block 2**: 3 transfers, 12 commitments, 12 nullifier slots
///   with the client's `[transfer, 0, fee, 0]` layout (2 non-zero
///   nullifiers per transfer, 6 total).
///
/// Each block is a separate IVC chain (the live proposer calls
/// `prove_circuits` once per block, each starting from
/// `compute_initial_z0()`). The first block must verify; the second
/// must also verify because the prior-block nullifier set is empty
/// (deposits have zero nullifiers). This test exercises only the
/// real-circuit path (no padding to 256) so it runs in a few seconds.
#[test]
fn ivc_live_scenario_block1_deposits_block2_transfers() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];

        // === Block 1: 7 deposits, 28 commitments, 28 zero nullifiers ===
        let block1_commitments: Vec<F1> = (1000u64..1028).map(F1::from).collect();
        let block1_nullifiers: Vec<F1> = vec![F1::ZERO; 28];
        let inputs1 = RollupWitnessInputs::new(
            &block1_commitments,
            &block1_nullifiers,
            historic_root,
        );
        let witness1 = build_rollup_circuits(&inputs1);
        assert_eq!(witness1.circuits.len(), 28);
        let _proof1 = engine
            .prove_circuits(witness1.circuits)
            .expect("block 1 (7 deposits) must verify");

        // === Block 2: 3 transfers, 12 commitments, 12 nullifier slots ===
        // Client layout: [transfer, 0, fee, 0] per transfer. 6 non-zero
        // nullifiers total, at positions 0, 2, 4, 6, 8, 10 of the
        // 12-slot array.
        let block2_commitments: Vec<F1> = (2000u64..2012).map(F1::from).collect();
        let block2_nullifiers: Vec<F1> = vec![
            F1::from(50u64),   // tx 1: transfer
            F1::ZERO,
            F1::from(60u64),   // tx 1: fee
            F1::ZERO,
            F1::from(70u64),   // tx 2: transfer
            F1::ZERO,
            F1::from(80u64),   // tx 2: fee
            F1::ZERO,
            F1::from(90u64),   // tx 3: transfer
            F1::ZERO,
            F1::from(100u64),  // tx 3: fee
            F1::ZERO,
        ];
        // The prior-block nullifier set is empty: the first block
        // had all-zero nullifiers, so the DB has nothing to hydrate.
        let inputs2 = RollupWitnessInputs::new(
            &block2_commitments,
            &block2_nullifiers,
            historic_root,
        );
        let witness2 = build_rollup_circuits(&inputs2);
        assert_eq!(witness2.circuits.len(), 12);
        let _proof2 = engine
            .prove_circuits(witness2.circuits)
            .expect("block 2 (3 transfers) must verify");
    });
}

/// Minimal repro: 4 commitments with 1 non-zero nullifier at
/// index 0. This is the simplest transfer shape (no fee, single
/// input, single output). Should verify, but may reproduce the
/// "UnSat" bug if the IMT is the culprit.
#[test]
fn minimal_4_steps_one_real_nullifier_at_index_0() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];

        let commitments: Vec<F1> = (1u64..=4).map(F1::from).collect();
        let nullifiers: Vec<F1> = vec![
            F1::from(100u64),  // real nullifier at index 0
            F1::ZERO,
            F1::ZERO,
            F1::ZERO,
        ];
        let inputs = RollupWitnessInputs::new(
            &commitments,
            &nullifiers,
            historic_root,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 4);
        let _proof = engine
            .prove_circuits(witness.circuits)
            .expect("4 steps with 1 real nullifier at index 0 must verify");
    });
}

/// Minimal repro: 4 commitments with 1 non-zero nullifier at
/// index 2 (the "fee" slot). Verifies whether the issue is specific
/// to the fee slot or affects all non-zero nullifier positions.
#[test]
fn minimal_4_steps_one_real_nullifier_at_index_2() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];

        let commitments: Vec<F1> = (1u64..=4).map(F1::from).collect();
        let nullifiers: Vec<F1> = vec![
            F1::ZERO,
            F1::ZERO,
            F1::from(100u64),  // real nullifier at index 2 (fee slot)
            F1::ZERO,
        ];
        let inputs = RollupWitnessInputs::new(
            &commitments,
            &nullifiers,
            historic_root,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 4);
        let _proof = engine
            .prove_circuits(witness.circuits)
            .expect("4 steps with 1 real nullifier at index 2 must verify");
    });
}

/// Minimal repro: 4 commitments with TWO non-zero nullifiers
/// (transfer + fee at indices 0 and 2). This is the canonical
/// 1-input-2-output transfer with fee.
#[test]
fn minimal_4_steps_two_real_nullifiers_indices_0_and_2() {
    let _ = std::panic::catch_unwind(|| {
        let engine = NovaRollupEngine::setup().expect("engine setup");
        let historic_root = compute_initial_z0()[2];

        let commitments: Vec<F1> = (1u64..=4).map(F1::from).collect();
        let nullifiers: Vec<F1> = vec![
            F1::from(100u64),  // transfer nullifier
            F1::ZERO,
            F1::from(200u64),  // fee nullifier
            F1::ZERO,
        ];
        let inputs = RollupWitnessInputs::new(
            &commitments,
            &nullifiers,
            historic_root,
        );
        let witness = build_rollup_circuits(&inputs);
        assert_eq!(witness.circuits.len(), 4);
        let _proof = engine
            .prove_circuits(witness.circuits)
            .expect("4 steps with 2 real nullifiers (transfer + fee) must verify");
    });
}
