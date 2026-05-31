//! Merkle-tree and Indexed-Merkle-Tree (IMT) gadgets for the Nova rollup
//! step circuit.
//!
//! ## Scope
//!
//! Two cryptographic checks must hold per rollup transaction:
//!
//! 1. **Commitment inclusion** — the new commitment appears at some path in
//!    the post-state `new_commitments_root`.  This is a classic binary
//!    Merkle inclusion proof.
//! 2. **Nullifier non-inclusion** — the new nullifier does **not** appear
//!    in the pre-state `old_nullifiers_root`.  Nightfall uses an *indexed*
//!    Merkle tree (low-leaf design), so non-inclusion is proved by
//!    exhibiting a "low leaf" `L` with
//!    `L.value < nullifier < L.next_value` (with `next_value == 0` treated
//!    as +∞ to handle the tail of the tree), plus an inclusion proof for
//!    `H(L.value, L.next_index, L.next_value)`.
//!
//! ## Hash function
//!
//! All hashing uses neptune Poseidon (arity 2) bundled with `nova-snark`.
//! See [`super::hash`] for the determinism contract between native and
//! in-circuit hashing.
//!
//! ## Caveat
//!
//! This module covers tasks **1.1.1** and **1.1.2** of the migration plan
//! (inclusion + non-inclusion).  It does **not** implement the IMT *update*
//! gadget (proving `old_nullifiers_root → new_nullifiers_root` is a
//! legitimate insertion of `nullifier`); that is a separate piece of work
//! tracked as a follow-up to this module.  Until that gadget lands, the
//! post-state nullifier root is asserted by the prover and bound only by
//! whatever consistency checks the IVC public-input layer enforces.

#![cfg(feature = "nova-v1")]

use ff::{PrimeField, PrimeFieldBits};
use generic_array::typenum::U2;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        poseidon::PoseidonConstants,
    },
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};

use crate::proving::nova_v1::hash::{
    poseidon_hash2_circuit, poseidon_hash2_native, poseidon_hash3_circuit,
    poseidon_hash3_native,
};

// ---------------------------------------------------------------------------
// Native helpers (witness generation, tests, off-chain root computation).
// ---------------------------------------------------------------------------

/// A single hop in a Merkle inclusion path.
///
/// `sibling` is the co-path node at that level; `is_right` is `true` when
/// **the current node is the right child** (so the sibling sits on the
/// left and must be hashed first).
#[derive(Debug, Clone, Copy)]
pub struct MerklePathHop<F: PrimeField> {
    pub sibling: F,
    pub is_right: bool,
}

/// Walk a binary Merkle inclusion path natively, returning the implied
/// root.  Used to build witness data and to cross-check the in-circuit
/// gadget in tests.
pub fn compute_merkle_root_native<F: PrimeField>(
    constants: &PoseidonConstants<F, U2>,
    leaf: F,
    path: &[MerklePathHop<F>],
) -> F {
    let mut current = leaf;
    for hop in path {
        let (left, right) = if hop.is_right {
            (hop.sibling, current)
        } else {
            (current, hop.sibling)
        };
        current = poseidon_hash2_native(constants, left, right);
    }
    current
}

/// Native indexed-Merkle-tree leaf hash:
/// `H(value, next_index, next_value)`.
pub fn imt_leaf_hash_native<F: PrimeField>(
    constants: &PoseidonConstants<F, U2>,
    value: F,
    next_index: F,
    next_value: F,
) -> F {
    poseidon_hash3_native(constants, value, next_index, next_value)
}

// ---------------------------------------------------------------------------
// Circuit helpers.
// ---------------------------------------------------------------------------

/// Conditionally swap two allocated numbers.
///
/// Returns `(a, b)` when `condition` is false and `(b, a)` when true.
/// This is a thin wrapper around bellpepper-core's
/// `AllocatedNum::conditionally_reverse` named for the Merkle use case.
fn conditional_swap<F, CS>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    condition: &Boolean,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    AllocatedNum::conditionally_reverse(cs.namespace(|| "cond_swap"), a, b, condition)
}

/// Enforce that `condition * (x - y) == 0`, i.e. when `condition` is true,
/// `x` and `y` must be equal.  Used to gate root checks on `!is_padding`.
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
        || "conditional_equal",
        |_| condition.lc(CS::one(), F::ONE),
        |lc| lc + x.get_variable() - y.get_variable(),
        |lc| lc,
    );
    Ok(())
}

/// Allocated form of a [`MerklePathHop`] for use inside `synthesize`.
pub struct AllocatedMerkleHop<F: PrimeField> {
    pub sibling: AllocatedNum<F>,
    pub is_right: Boolean,
}

impl<F: PrimeField> AllocatedMerkleHop<F> {
    pub fn alloc<CS: ConstraintSystem<F>>(
        mut cs: CS,
        hop: MerklePathHop<F>,
    ) -> Result<Self, SynthesisError> {
        let sibling = AllocatedNum::alloc(cs.namespace(|| "sibling"), || Ok(hop.sibling))?;
        let bit = AllocatedBit::alloc(cs.namespace(|| "is_right"), Some(hop.is_right))?;
        Ok(Self {
            sibling,
            is_right: Boolean::from(bit),
        })
    }
}

/// In-circuit binary Merkle inclusion check, gated on `enabled`.
///
/// Computes the root implied by `leaf` and `path` (length determines depth)
/// and, when `enabled` is true, enforces it equals `expected_root`.  When
/// `enabled` is false the equality is **not** enforced — this lets padding
/// steps reuse the same R1CS shape with all-zero witnesses without forcing
/// the root to a particular value.
///
/// The number of constraints emitted is independent of `enabled`'s value
/// (the gate is multiplicative, not branchy), which is required for Nova
/// IVC to fold steps uniformly.
pub fn verify_merkle_inclusion_circuit<F, CS>(
    constants: &PoseidonConstants<F, U2>,
    mut cs: CS,
    leaf: &AllocatedNum<F>,
    path: &[AllocatedMerkleHop<F>],
    expected_root: &AllocatedNum<F>,
    enabled: &Boolean,
) -> Result<(), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut current = leaf.clone();
    for (i, hop) in path.iter().enumerate() {
        let mut ns = cs.namespace(|| format!("level_{i}"));
        let (left, right) =
            conditional_swap(ns.namespace(|| "swap"), &current, &hop.sibling, &hop.is_right)?;
        current = poseidon_hash2_circuit(
            constants,
            ns.namespace(|| "hash"),
            &left,
            &right,
        )?;
    }
    conditional_assert_equal(
        cs.namespace(|| "root_eq"),
        enabled,
        &current,
        expected_root,
    )
}

// ---------------------------------------------------------------------------
// Indexed-Merkle-Tree non-inclusion.
// ---------------------------------------------------------------------------

/// Native witness for a single IMT non-inclusion proof.
///
/// Holds the low-leaf record and the inclusion path that proves it lives
/// in the pre-state `old_nullifiers_root`.
#[derive(Debug, Clone)]
pub struct ImtNonInclusionWitness<F: PrimeField> {
    pub nullifier: F,
    pub low_value: F,
    pub low_next_index: F,
    pub low_next_value: F,
    pub path: Vec<MerklePathHop<F>>,
}

/// Allocated form of [`ImtNonInclusionWitness`].
pub struct AllocatedImtNonInclusion<F: PrimeField> {
    pub nullifier: AllocatedNum<F>,
    pub low_value: AllocatedNum<F>,
    pub low_next_index: AllocatedNum<F>,
    pub low_next_value: AllocatedNum<F>,
    pub path: Vec<AllocatedMerkleHop<F>>,
}

impl<F: PrimeField> AllocatedImtNonInclusion<F> {
    pub fn alloc<CS: ConstraintSystem<F>>(
        mut cs: CS,
        witness: &ImtNonInclusionWitness<F>,
    ) -> Result<Self, SynthesisError> {
        let nullifier =
            AllocatedNum::alloc(cs.namespace(|| "nullifier"), || Ok(witness.nullifier))?;
        let low_value =
            AllocatedNum::alloc(cs.namespace(|| "low_value"), || Ok(witness.low_value))?;
        let low_next_index = AllocatedNum::alloc(cs.namespace(|| "low_next_index"), || {
            Ok(witness.low_next_index)
        })?;
        let low_next_value = AllocatedNum::alloc(cs.namespace(|| "low_next_value"), || {
            Ok(witness.low_next_value)
        })?;
        let mut path = Vec::with_capacity(witness.path.len());
        for (i, hop) in witness.path.iter().enumerate() {
            path.push(AllocatedMerkleHop::alloc(
                cs.namespace(|| format!("hop_{i}")),
                *hop,
            )?);
        }
        Ok(Self {
            nullifier,
            low_value,
            low_next_index,
            low_next_value,
            path,
        })
    }
}

/// Enforce that `a < b` as field elements, by checking
/// `(b - a - 1)` fits in `num_bits` bits.  Caller must guarantee both `a`
/// and `b` live below `2^num_bits` for the check to be meaningful; for
/// nullifiers we conservatively use `num_bits = 253` (BN254 Fr is
/// 254-bit), but tests use smaller bounds.
///
/// Emits exactly `num_bits` boolean-allocation constraints plus a
/// linear-combination consistency constraint, regardless of values.
fn enforce_less_than<F, CS>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    // diff = b - a - 1
    let diff_val = match (b.get_value(), a.get_value()) {
        (Some(bv), Some(av)) => Some(bv - av - F::ONE),
        _ => None,
    };
    let diff = AllocatedNum::alloc(cs.namespace(|| "lt_diff"), || {
        diff_val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    // Constrain: diff + a + 1 == b
    cs.enforce(
        || "lt_diff_def",
        |lc| lc + diff.get_variable() + a.get_variable() + CS::one(),
        |lc| lc + CS::one(),
        |lc| lc + b.get_variable(),
    );
    // Decompose `diff` into `num_bits` bits — succeeds iff diff ∈ [0, 2^num_bits),
    // which forces b > a (and b - a ≤ 2^num_bits).
    let bits = diff.to_bits_le(cs.namespace(|| "lt_diff_bits"))?;
    // `to_bits_le` does not enforce that the bit decomposition is canonical
    // for values ≥ p, but caller's value bounds (num_bits < log2(p)) avoid
    // that pitfall.  We just need at most `num_bits` bits.
    debug_assert_eq!(bits.len(), F::NUM_BITS as usize);
    // No additional constraints — `to_bits_le` truncates to the field size
    // and binds the integer encoding to `diff`.  By construction the value
    // satisfies the range constraint when num_bits ≤ F::NUM_BITS.
    // For a strict `num_bits` bound, enforce the top bits are zero:
    for (i, bit) in bits.iter().enumerate().skip(num_bits) {
        Boolean::enforce_equal(
            cs.namespace(|| format!("lt_top_bit_{i}_zero")),
            bit,
            &Boolean::constant(false),
        )?;
    }
    Ok(())
}

/// Conditionally enforce `a < b`, gated on `enabled`.  When `enabled` is
/// false the constraint is trivially satisfied; the number of constraints
/// emitted is the same either way (uniform R1CS shape).
fn conditional_enforce_less_than<F, CS>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    num_bits: usize,
    enabled: &Boolean,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    // Allocate masked operands:  a_eff = enabled ? a : 0,  b_eff = enabled ? b : 1.
    // When disabled the trivial inequality 0 < 1 holds and the bit
    // decomposition succeeds with constant bits.
    let enabled_val = enabled.get_value();
    let a_val = a.get_value();
    let b_val = b.get_value();
    let mask = |on: bool, real: Option<F>, off: F| -> Option<F> {
        match (enabled_val, real) {
            (Some(e), Some(r)) => Some(if e == on { r } else { off }),
            _ => None,
        }
    };
    let a_eff_val = mask(true, a_val, F::ZERO);
    let b_eff_val = mask(true, b_val, F::ONE);
    let a_eff = AllocatedNum::alloc(cs.namespace(|| "a_eff"), || {
        a_eff_val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    let b_eff = AllocatedNum::alloc(cs.namespace(|| "b_eff"), || {
        b_eff_val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    // a_eff = enabled * a   (when enabled=0, a_eff must be 0)
    cs.enforce(
        || "a_eff_def",
        |_| enabled.lc(CS::one(), F::ONE),
        |lc| lc + a.get_variable(),
        |lc| lc + a_eff.get_variable(),
    );
    // b_eff = enabled * b + (1 - enabled) * 1
    //       = enabled * (b - 1) + 1
    cs.enforce(
        || "b_eff_def",
        |_| enabled.lc(CS::one(), F::ONE),
        |lc| lc + b.get_variable() - CS::one(),
        |lc| lc + b_eff.get_variable() - CS::one(),
    );
    enforce_less_than(cs.namespace(|| "lt"), &a_eff, &b_eff, num_bits)
}

/// `is_zero(x)` — returns a `Boolean` that is true exactly when `x == 0`.
///
/// Standard zero-test gadget: introduces an auxiliary inverse witness
/// `inv` so that `x * inv == 1 - is_zero` and `x * is_zero == 0`.
fn is_zero<F, CS>(
    mut cs: CS,
    x: &AllocatedNum<F>,
) -> Result<Boolean, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let x_val = x.get_value();
    let is_zero_val = x_val.map(|v| v.is_zero().into());
    let inv_val = x_val.map(|v| v.invert().unwrap_or(F::ZERO));

    let is_zero_bit = AllocatedBit::alloc(cs.namespace(|| "is_zero_bit"), is_zero_val)?;
    let inv = AllocatedNum::alloc(cs.namespace(|| "inv"), || {
        inv_val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    // x * inv = 1 - is_zero
    cs.enforce(
        || "x_inv_def",
        |lc| lc + x.get_variable(),
        |lc| lc + inv.get_variable(),
        |lc| lc + CS::one() - is_zero_bit.get_variable(),
    );
    // x * is_zero = 0
    cs.enforce(
        || "x_iszero_zero",
        |lc| lc + x.get_variable(),
        |lc| lc + is_zero_bit.get_variable(),
        |lc| lc,
    );
    Ok(Boolean::from(is_zero_bit))
}

/// In-circuit IMT non-inclusion check, gated on `enabled`.
///
/// Performs three things (all gated on `enabled`):
///
/// 1. Computes `low_leaf_hash = H(low_value, low_next_index, low_next_value)`
///    and enforces it sits at `path` in `old_nullifiers_root`.
/// 2. Enforces `low_value < nullifier` (the low leaf is strictly below).
/// 3. Enforces `low_next_value == 0  ∨  nullifier < low_next_value`
///    (the low leaf is the immediate predecessor — there's no other leaf
///    between it and `nullifier`).
///
/// Together these prove `nullifier` is **not** a leaf of the tree rooted
/// at `old_nullifiers_root`.
///
/// `num_bits` bounds the size of nullifier / low-leaf values for the
/// less-than checks; pass `253` in production (BN254 Fr is 254-bit).
pub fn verify_imt_non_inclusion_circuit<F, CS>(
    constants: &PoseidonConstants<F, U2>,
    mut cs: CS,
    witness: &AllocatedImtNonInclusion<F>,
    old_nullifiers_root: &AllocatedNum<F>,
    num_bits: usize,
    enabled: &Boolean,
) -> Result<(), SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    // 1. Compute the low-leaf hash and prove inclusion in old root.
    let low_leaf_hash = poseidon_hash3_circuit(
        constants,
        cs.namespace(|| "low_leaf_hash"),
        &witness.low_value,
        &witness.low_next_index,
        &witness.low_next_value,
    )?;
    verify_merkle_inclusion_circuit(
        constants,
        cs.namespace(|| "low_leaf_inclusion"),
        &low_leaf_hash,
        &witness.path,
        old_nullifiers_root,
        enabled,
    )?;

    // 2. low_value < nullifier
    conditional_enforce_less_than(
        cs.namespace(|| "lt_low_below_nullifier"),
        &witness.low_value,
        &witness.nullifier,
        num_bits,
        enabled,
    )?;

    // 3. low_next_value == 0  ∨  nullifier < low_next_value
    //    Compute the OR by gating the < check on (enabled AND !next_is_zero).
    let next_is_zero = is_zero(
        cs.namespace(|| "next_is_zero"),
        &witness.low_next_value,
    )?;
    let next_is_nonzero = next_is_zero.not();
    let upper_check_enabled = Boolean::and(
        cs.namespace(|| "and_enabled_and_nonzero"),
        enabled,
        &next_is_nonzero,
    )?;
    conditional_enforce_less_than(
        cs.namespace(|| "lt_nullifier_below_next"),
        &witness.nullifier,
        &witness.low_next_value,
        num_bits,
        &upper_check_enabled,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::nova_v1::hash::poseidon_constants;
    use ff::Field;
    use nova_snark::{
        frontend::{test_cs::TestConstraintSystem, ConstraintSystem},
        provider::Bn256EngineKZG,
        traits::Engine,
    };

    type F = <Bn256EngineKZG as Engine>::Scalar;

    /// Build a small fixed-depth tree and the inclusion path for `leaf_idx`.
    /// Tree has `2^depth` leaves; non-occupied slots are filled with zero.
    fn build_path(
        constants: &PoseidonConstants<F, U2>,
        leaves: &[F],
        depth: usize,
        leaf_idx: usize,
    ) -> (F, Vec<MerklePathHop<F>>) {
        assert!(leaves.len() <= 1 << depth);
        let mut layer: Vec<F> = leaves.to_vec();
        // pad to 2^depth with zeros
        layer.resize(1 << depth, F::ZERO);

        let mut idx = leaf_idx;
        let mut path = Vec::with_capacity(depth);
        let mut current = layer.clone();
        for _ in 0..depth {
            let is_right = idx & 1 == 1;
            let sibling = if is_right { current[idx - 1] } else { current[idx + 1] };
            path.push(MerklePathHop { sibling, is_right });
            // hash layer up
            let next = current
                .chunks(2)
                .map(|c| poseidon_hash2_native(constants, c[0], c[1]))
                .collect::<Vec<_>>();
            current = next;
            idx /= 2;
        }
        assert_eq!(current.len(), 1);
        (current[0], path)
    }

    #[test]
    fn native_path_matches_recomputation() {
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, path) = build_path(&constants, &leaves, 3, 5);
        let recomputed = compute_merkle_root_native(&constants, leaves[5], &path);
        assert_eq!(root, recomputed);
    }

    #[test]
    fn circuit_inclusion_accepts_valid_path() {
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, path) = build_path(&constants, &leaves, 3, 3);

        let mut cs = TestConstraintSystem::<F>::new();
        let leaf = AllocatedNum::alloc_infallible(cs.namespace(|| "leaf"), || leaves[3]);
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc_path: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, h)| {
                AllocatedMerkleHop::alloc(cs.namespace(|| format!("hop_{i}")), *h).unwrap()
            })
            .collect();
        let enabled = Boolean::constant(true);
        verify_merkle_inclusion_circuit(
            &constants,
            cs.namespace(|| "inclusion"),
            &leaf,
            &alloc_path,
            &root_alloc,
            &enabled,
        )
        .unwrap();
        assert!(cs.is_satisfied(), "valid path must satisfy: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn circuit_inclusion_rejects_tampered_sibling() {
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, mut path) = build_path(&constants, &leaves, 3, 3);
        // Flip a sibling — should break the root.
        path[1].sibling += F::ONE;

        let mut cs = TestConstraintSystem::<F>::new();
        let leaf = AllocatedNum::alloc_infallible(cs.namespace(|| "leaf"), || leaves[3]);
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc_path: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, h)| {
                AllocatedMerkleHop::alloc(cs.namespace(|| format!("hop_{i}")), *h).unwrap()
            })
            .collect();
        let enabled = Boolean::constant(true);
        verify_merkle_inclusion_circuit(
            &constants,
            cs.namespace(|| "inclusion"),
            &leaf,
            &alloc_path,
            &root_alloc,
            &enabled,
        )
        .unwrap();
        assert!(!cs.is_satisfied(), "tampered sibling must NOT satisfy");
    }

    #[test]
    fn circuit_inclusion_rejects_tampered_direction() {
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, mut path) = build_path(&constants, &leaves, 3, 3);
        path[0].is_right = !path[0].is_right; // flip direction bit

        let mut cs = TestConstraintSystem::<F>::new();
        let leaf = AllocatedNum::alloc_infallible(cs.namespace(|| "leaf"), || leaves[3]);
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc_path: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, h)| {
                AllocatedMerkleHop::alloc(cs.namespace(|| format!("hop_{i}")), *h).unwrap()
            })
            .collect();
        let enabled = Boolean::constant(true);
        verify_merkle_inclusion_circuit(
            &constants,
            cs.namespace(|| "inclusion"),
            &leaf,
            &alloc_path,
            &root_alloc,
            &enabled,
        )
        .unwrap();
        assert!(!cs.is_satisfied(), "flipped direction must NOT satisfy");
    }

    #[test]
    fn circuit_inclusion_rejects_wrong_leaf() {
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, path) = build_path(&constants, &leaves, 3, 3);

        let mut cs = TestConstraintSystem::<F>::new();
        // Wrong leaf value
        let leaf = AllocatedNum::alloc_infallible(cs.namespace(|| "leaf"), || F::from(99u64));
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc_path: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, h)| {
                AllocatedMerkleHop::alloc(cs.namespace(|| format!("hop_{i}")), *h).unwrap()
            })
            .collect();
        let enabled = Boolean::constant(true);
        verify_merkle_inclusion_circuit(
            &constants,
            cs.namespace(|| "inclusion"),
            &leaf,
            &alloc_path,
            &root_alloc,
            &enabled,
        )
        .unwrap();
        assert!(!cs.is_satisfied(), "wrong leaf must NOT satisfy");
    }

    #[test]
    fn disabled_inclusion_accepts_garbage() {
        // When enabled = false, the gadget MUST allow arbitrary witnesses
        // (this is what lets padding steps share the IVC shape with real steps).
        let constants = poseidon_constants::<F>();
        let leaves: Vec<F> = (1..=8u64).map(F::from).collect();
        let (root, mut path) = build_path(&constants, &leaves, 3, 3);
        path[0].sibling += F::from(424242u64); // garbage

        let mut cs = TestConstraintSystem::<F>::new();
        let leaf = AllocatedNum::alloc_infallible(cs.namespace(|| "leaf"), || leaves[3]);
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc_path: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, h)| {
                AllocatedMerkleHop::alloc(cs.namespace(|| format!("hop_{i}")), *h).unwrap()
            })
            .collect();
        let enabled = Boolean::constant(false);
        verify_merkle_inclusion_circuit(
            &constants,
            cs.namespace(|| "inclusion"),
            &leaf,
            &alloc_path,
            &root_alloc,
            &enabled,
        )
        .unwrap();
        assert!(cs.is_satisfied(), "disabled inclusion must accept anything");
    }

    // ----- IMT non-inclusion tests -----

    /// Build a tiny IMT of depth 3 from three nullifier values; returns
    /// (root, leaves[]) so callers can craft non-inclusion proofs against it.
    fn build_imt(
        constants: &PoseidonConstants<F, U2>,
        values: &[F],
        depth: usize,
    ) -> (F, Vec<F>) {
        // Sort values; index 0 is the canonical zero "head" leaf.
        let sorted: Vec<F> = std::iter::once(F::ZERO).chain(values.iter().copied()).collect();
        // (already sorted in our tests since we pick monotonic inputs)
        // Build leaf hashes: for each leaf, next_value is the next entry (or 0 at the tail).
        let mut leaves = Vec::with_capacity(sorted.len());
        for i in 0..sorted.len() {
            let value = sorted[i];
            let next_index = F::from((i + 1) as u64 % (1u64 << depth));
            let next_value = if i + 1 < sorted.len() {
                sorted[i + 1]
            } else {
                F::ZERO
            };
            leaves.push(imt_leaf_hash_native(constants, value, next_index, next_value));
        }
        // Pad to 2^depth with zeros; compute root using build_path machinery.
        let mut padded = leaves.clone();
        padded.resize(1 << depth, F::ZERO);
        let (root, _) = build_path(constants, &padded, depth, 0);
        // Drop variable
        let _ = sorted;
        (root, padded)
    }

    /// Compares two BN254 Fr field elements as integers via their bytes.
    /// For sorted_values used in tests we just pick small integers so
    /// natural Ord on the underlying integer holds.
    fn cmp_fr(a: &F, b: &F) -> std::cmp::Ordering {
        let abytes = a.to_repr();
        let bbytes = b.to_repr();
        // little-endian repr — compare from MSB down
        for (x, y) in abytes.as_ref().iter().rev().zip(bbytes.as_ref().iter().rev()) {
            match x.cmp(y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Picks a non-inclusion witness using cmp_fr-based ordering.
    fn pick_witness(
        constants: &PoseidonConstants<F, U2>,
        depth: usize,
        sorted_values: &[F],
        leaves: &[F],
        nullifier: F,
    ) -> (F, ImtNonInclusionWitness<F>) {
        let mut low_idx = 0;
        for (i, v) in sorted_values.iter().enumerate() {
            if cmp_fr(v, &nullifier) == std::cmp::Ordering::Less {
                low_idx = i;
            }
        }
        let low_value = sorted_values[low_idx];
        let next_index = F::from(((low_idx + 1) as u64) % (1u64 << depth));
        let low_next_value = sorted_values.get(low_idx + 1).copied().unwrap_or(F::ZERO);
        let (root, path) = build_path(constants, leaves, depth, low_idx);
        (
            root,
            ImtNonInclusionWitness {
                nullifier,
                low_value,
                low_next_index: next_index,
                low_next_value,
                path,
            },
        )
    }

    #[test]
    fn imt_non_inclusion_accepts_valid_witness() {
        let constants = poseidon_constants::<F>();
        let depth = 3;
        let sorted = vec![F::ZERO, F::from(10u64), F::from(50u64), F::from(100u64)];
        let (_root, leaves) = build_imt(&constants, &[F::from(10u64), F::from(50u64), F::from(100u64)], depth);
        let nullifier = F::from(30u64); // between 10 and 50
        let (root, witness) = pick_witness(&constants, depth, &sorted, &leaves, nullifier);

        let mut cs = TestConstraintSystem::<F>::new();
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc = AllocatedImtNonInclusion::alloc(cs.namespace(|| "wit"), &witness).unwrap();
        let enabled = Boolean::constant(true);
        verify_imt_non_inclusion_circuit(
            &constants,
            cs.namespace(|| "non_incl"),
            &alloc,
            &root_alloc,
            16, // small bit bound for small test values
            &enabled,
        )
        .unwrap();
        assert!(cs.is_satisfied(), "valid non-inclusion must satisfy: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn imt_non_inclusion_rejects_when_nullifier_equals_low_value() {
        // If nullifier == low_value, the < check `low_value < nullifier` fails.
        let constants = poseidon_constants::<F>();
        let depth = 3;
        let sorted = vec![F::ZERO, F::from(10u64), F::from(50u64)];
        let (_root, leaves) = build_imt(&constants, &[F::from(10u64), F::from(50u64)], depth);
        // Build a witness for nullifier=50 but pick low_idx pointing at 50:
        let (root, mut witness) = pick_witness(&constants, depth, &sorted, &leaves, F::from(30u64));
        // tamper: claim nullifier == low_value
        witness.nullifier = witness.low_value;

        let mut cs = TestConstraintSystem::<F>::new();
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc = AllocatedImtNonInclusion::alloc(cs.namespace(|| "wit"), &witness).unwrap();
        let enabled = Boolean::constant(true);
        verify_imt_non_inclusion_circuit(
            &constants,
            cs.namespace(|| "non_incl"),
            &alloc,
            &root_alloc,
            16,
            &enabled,
        )
        .unwrap();
        assert!(!cs.is_satisfied(), "nullifier == low_value must fail range check");
    }

    #[test]
    fn imt_non_inclusion_rejects_when_low_leaf_path_tampered() {
        let constants = poseidon_constants::<F>();
        let depth = 3;
        let sorted = vec![F::ZERO, F::from(10u64), F::from(50u64)];
        let (_root, leaves) = build_imt(&constants, &[F::from(10u64), F::from(50u64)], depth);
        let (root, mut witness) = pick_witness(&constants, depth, &sorted, &leaves, F::from(30u64));
        // tamper: corrupt one sibling
        witness.path[0].sibling += F::ONE;

        let mut cs = TestConstraintSystem::<F>::new();
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc = AllocatedImtNonInclusion::alloc(cs.namespace(|| "wit"), &witness).unwrap();
        let enabled = Boolean::constant(true);
        verify_imt_non_inclusion_circuit(
            &constants,
            cs.namespace(|| "non_incl"),
            &alloc,
            &root_alloc,
            16,
            &enabled,
        )
        .unwrap();
        assert!(!cs.is_satisfied(), "tampered low-leaf path must fail inclusion");
    }

    #[test]
    fn imt_non_inclusion_accepts_tail_nullifier_with_zero_next() {
        // When low_next_value == 0 (tail of the tree), upper bound is +∞,
        // so any nullifier > low_value should pass.
        let constants = poseidon_constants::<F>();
        let depth = 3;
        let sorted = vec![F::ZERO, F::from(10u64), F::from(50u64)];
        let (_root, leaves) = build_imt(&constants, &[F::from(10u64), F::from(50u64)], depth);
        let nullifier = F::from(99u64); // beyond the last leaf
        let (root, witness) = pick_witness(&constants, depth, &sorted, &leaves, nullifier);
        assert_eq!(witness.low_next_value, F::ZERO, "should pick the tail leaf");

        let mut cs = TestConstraintSystem::<F>::new();
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc = AllocatedImtNonInclusion::alloc(cs.namespace(|| "wit"), &witness).unwrap();
        let enabled = Boolean::constant(true);
        verify_imt_non_inclusion_circuit(
            &constants,
            cs.namespace(|| "non_incl"),
            &alloc,
            &root_alloc,
            16,
            &enabled,
        )
        .unwrap();
        assert!(cs.is_satisfied(), "tail-nullifier must satisfy: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn disabled_non_inclusion_accepts_anything() {
        let constants = poseidon_constants::<F>();
        let depth = 3;
        let sorted = vec![F::ZERO, F::from(10u64), F::from(50u64)];
        let (_root, leaves) = build_imt(&constants, &[F::from(10u64), F::from(50u64)], depth);
        let (root, mut witness) = pick_witness(&constants, depth, &sorted, &leaves, F::from(30u64));
        // tamper everything
        witness.path[0].sibling += F::from(1_000_000u64);
        witness.low_value = F::from(99_999u64);

        let mut cs = TestConstraintSystem::<F>::new();
        let root_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "root"), || root);
        let alloc = AllocatedImtNonInclusion::alloc(cs.namespace(|| "wit"), &witness).unwrap();
        let enabled = Boolean::constant(false);
        verify_imt_non_inclusion_circuit(
            &constants,
            cs.namespace(|| "non_incl"),
            &alloc,
            &root_alloc,
            16,
            &enabled,
        )
        .unwrap();
        assert!(cs.is_satisfied(), "disabled non-inclusion must accept anything");
    }
}
