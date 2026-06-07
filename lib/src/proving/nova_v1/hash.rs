//! Poseidon hash helpers for the Nova rollup step circuit.
//!
//! This module exposes a tiny, focused API around the [neptune] Poseidon
//! implementation bundled with `nova-snark` at
//! [`nova_snark::frontend::gadgets::poseidon`].  We need exactly two hash
//! shapes for the rollup circuit:
//!
//! - `hash2(left, right) -> F` for Merkle-tree internal nodes (arity 2).
//! - `hash3(value, next_index, next_value) -> F` for indexed-Merkle-tree
//!   leaves (used by the nullifier non-inclusion gadget).
//!
//! Both shapes are provided in two flavours that **must** agree element
//! for element:
//!
//! - `*_native`  — out-of-circuit Rust function used for witness generation,
//!   on-chain root computation (off-chain), and tests.
//! - `*_circuit` — bellpepper-core R1CS gadget used inside `synthesize`.
//!
//! ## Determinism contract
//!
//! Native and circuit must hash to the **identical** field element for any
//! given preimage.  This is enforced by:
//!
//! 1. Same Poseidon parameters: `Strength::Standard`, arity `U2`,
//!    `HashType::Sponge` (the default produced by
//!    [`Sponge::api_constants`]).
//! 2. Identical sponge I/O pattern: `Absorb(n)` then `Squeeze(1)` for the
//!    same `n` in both flavours.
//! 3. Identical default domain separator (`None` → `0`).
//!
//! Round-trip tests in `tests` below cross-check this.
//!
//! [neptune]: https://github.com/argumentcomputer/neptune

#![cfg(feature = "nova-v1")]

use ff::PrimeField;
use generic_array::typenum::U2;
use nova_snark::frontend::{
    gadgets::poseidon::{
        Elt, IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp,
        SpongeTrait, Strength,
    },
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};

/// Build (or reuse) the standard-strength sponge constants for arity 2.
///
/// These constants are derived purely from arity + strength + hash type and
/// contain no secret material, but they are non-trivial to derive
/// (round-constant generation runs Grain LFSR).  Callers that hash many
/// times in a row should cache the returned value.
pub fn poseidon_constants<F: PrimeField>() -> PoseidonConstants<F, U2> {
    Sponge::<F, U2>::api_constants(Strength::Standard)
}

// ---------------------------------------------------------------------------
// Native (out-of-circuit) hashing.
// ---------------------------------------------------------------------------

/// Native arity-2 Poseidon hash: `out = H(a, b)`.
pub fn poseidon_hash2_native<F: PrimeField>(constants: &PoseidonConstants<F, U2>, a: F, b: F) -> F {
    let mut sponge = Sponge::<F, U2>::new_with_constants(constants, Simplex);
    let acc = &mut ();
    let pattern = IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]);
    sponge.start(pattern, None, acc);
    SpongeAPI::absorb(&mut sponge, 2, &[a, b], acc);
    let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).expect("sponge finish (hash2 native)");
    out[0]
}

/// Native three-input Poseidon hash: `out = H(a, b, c)`.
///
/// Used to derive an indexed-Merkle-tree leaf hash from
/// `(value, next_index, next_value)`.  With arity `U2` the sponge handles
/// the over-rate absorb internally — both native and circuit follow the
/// same pattern, so the result matches.
pub fn poseidon_hash3_native<F: PrimeField>(
    constants: &PoseidonConstants<F, U2>,
    a: F,
    b: F,
    c: F,
) -> F {
    let mut sponge = Sponge::<F, U2>::new_with_constants(constants, Simplex);
    let acc = &mut ();
    let pattern = IOPattern(vec![SpongeOp::Absorb(3), SpongeOp::Squeeze(1)]);
    sponge.start(pattern, None, acc);
    SpongeAPI::absorb(&mut sponge, 3, &[a, b, c], acc);
    let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).expect("sponge finish (hash3 native)");
    out[0]
}

// ---------------------------------------------------------------------------
// In-circuit hashing.
// ---------------------------------------------------------------------------

/// In-circuit arity-2 Poseidon hash.
///
/// Returns a freshly allocated variable constrained to equal
/// `H(a, b)` over the same parameters as [`poseidon_hash2_native`].
pub fn poseidon_hash2_circuit<F, CS>(
    constants: &PoseidonConstants<F, U2>,
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut ns = cs.namespace(|| "poseidon_hash2");
    let pattern = IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]);
    let elt = vec![Elt::Allocated(a.clone()), Elt::Allocated(b.clone())];
    let out_elt = {
        let mut sponge = SpongeCircuit::<F, U2, _>::new_with_constants(constants, Simplex);
        let acc = &mut ns;
        sponge.start(pattern, None, acc);
        SpongeAPI::absorb(&mut sponge, 2, &elt, acc);
        let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).expect("sponge finish (hash2 circuit)");
        out[0].clone()
    };
    let result = Elt::ensure_allocated(&out_elt, &mut ns.namespace(|| "ensure_allocated"));
    result
}

/// In-circuit three-input Poseidon hash, matching [`poseidon_hash3_native`].
pub fn poseidon_hash3_circuit<F, CS>(
    constants: &PoseidonConstants<F, U2>,
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    c: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut ns = cs.namespace(|| "poseidon_hash3");
    let pattern = IOPattern(vec![SpongeOp::Absorb(3), SpongeOp::Squeeze(1)]);
    let elt = vec![
        Elt::Allocated(a.clone()),
        Elt::Allocated(b.clone()),
        Elt::Allocated(c.clone()),
    ];
    let out_elt = {
        let mut sponge = SpongeCircuit::<F, U2, _>::new_with_constants(constants, Simplex);
        let acc = &mut ns;
        sponge.start(pattern, None, acc);
        SpongeAPI::absorb(&mut sponge, 3, &elt, acc);
        let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).expect("sponge finish (hash3 circuit)");
        out[0].clone()
    };
    let result = Elt::ensure_allocated(&out_elt, &mut ns.namespace(|| "ensure_allocated"));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use nova_snark::{
        frontend::{test_cs::TestConstraintSystem, ConstraintSystem},
        provider::Bn256EngineKZG,
        traits::Engine,
    };

    type F = <Bn256EngineKZG as Engine>::Scalar;

    /// `H(a, b)` must produce the same field element natively and in-circuit.
    #[test]
    fn hash2_native_matches_circuit() {
        let constants = poseidon_constants::<F>();
        let a = F::from(7u64);
        let b = F::from(13u64);

        let native = poseidon_hash2_native(&constants, a, b);

        let mut cs = TestConstraintSystem::<F>::new();
        let a_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "a"), || a);
        let b_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "b"), || b);
        let out = poseidon_hash2_circuit(&constants, cs.namespace(|| "hash"), &a_alloc, &b_alloc)
            .unwrap();
        assert!(
            cs.is_satisfied(),
            "circuit unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
        assert_eq!(
            out.get_value().unwrap(),
            native,
            "circuit hash != native hash"
        );
    }

    /// `H(a, b, c)` must produce the same field element natively and in-circuit.
    #[test]
    fn hash3_native_matches_circuit() {
        let constants = poseidon_constants::<F>();
        let a = F::from(2u64);
        let b = F::from(3u64);
        let c = F::from(5u64);

        let native = poseidon_hash3_native(&constants, a, b, c);

        let mut cs = TestConstraintSystem::<F>::new();
        let a_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "a"), || a);
        let b_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "b"), || b);
        let c_alloc = AllocatedNum::alloc_infallible(cs.namespace(|| "c"), || c);
        let out = poseidon_hash3_circuit(
            &constants,
            cs.namespace(|| "hash"),
            &a_alloc,
            &b_alloc,
            &c_alloc,
        )
        .unwrap();
        assert!(
            cs.is_satisfied(),
            "circuit unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
        assert_eq!(out.get_value().unwrap(), native);
    }

    /// Sanity: hashing different inputs gives different outputs.
    #[test]
    fn hash2_is_collision_free_on_smoke_inputs() {
        let constants = poseidon_constants::<F>();
        let h1 = poseidon_hash2_native(&constants, F::ZERO, F::ZERO);
        let h2 = poseidon_hash2_native(&constants, F::ZERO, F::ONE);
        let h3 = poseidon_hash2_native(&constants, F::ONE, F::ZERO);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3, "Poseidon must be order-sensitive");
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use ff::Field;
    use nova_snark::provider::Bn256EngineKZG;
    use nova_snark::traits::Engine;

    type F = <Bn256EngineKZG as Engine>::Scalar;

    /// Helper: build an arbitrary field element from 32 symbolic bytes.
    /// If the bytes are not canonical (>= modulus) we fall back to ZERO
    /// so the proof still covers all canonical values.
    fn any_f() -> F {
        let bytes = kani::any::<[u8; 32]>();
        let mut repr = F::ZERO.to_repr();
        repr.as_mut().copy_from_slice(&bytes);
        F::from_repr(repr).unwrap_or(F::ZERO)
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn prove_poseidon_hash2_native_no_panic() {
        let constants = poseidon_constants::<F>();
        let a = any_f();
        let b = any_f();
        let _out = poseidon_hash2_native(&constants, a, b);
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn prove_poseidon_hash3_native_no_panic() {
        let constants = poseidon_constants::<F>();
        let a = any_f();
        let b = any_f();
        let c = any_f();
        let _out = poseidon_hash3_native(&constants, a, b, c);
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn prove_poseidon_constants_idempotent() {
        // Poseidon constants are pure functions of arity + strength.
        // Calling twice must yield identical constants.
        let c1 = poseidon_constants::<F>();
        let c2 = poseidon_constants::<F>();
        // We cannot directly compare PoseidonConstants (it lacks Eq),
        // but we can verify hashing with both produces identical results.
        let a = any_f();
        let b = any_f();
        let h1 = poseidon_hash2_native(&c1, a, b);
        let h2 = poseidon_hash2_native(&c2, a, b);
        assert_eq!(h1, h2, "poseidon_constants must be deterministic");
    }
}
