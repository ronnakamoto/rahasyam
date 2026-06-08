//! Poseidon hash wrappers.
//!
//! Nightfall uses `jf_primitives::Poseidon`, which is the circomlib/iden3 Poseidon
//! over BN254. The noir-lang `poseidon` library implements the identical
//! permutation, so these fixed-arity wrappers are parity-equivalent to the
//! Nightfish in-circuit `PoseidonHashGadget`. Parity is asserted in `tests.nr`
//! against vectors produced by the real `jf_primitives::Poseidon` (see `../rust`).

use poseidon::poseidon::bn254;

/// Poseidon over 2 field elements.
pub fn hash2(a: Field, b: Field) -> Field {
    bn254::hash_2([a, b])
}

/// Poseidon over 3 field elements.
pub fn hash3(a: Field, b: Field, c: Field) -> Field {
    bn254::hash_3([a, b, c])
}

/// Poseidon over 4 field elements.
pub fn hash4(a: Field, b: Field, c: Field, d: Field) -> Field {
    bn254::hash_4([a, b, c, d])
}

/// Poseidon over 5 field elements.
pub fn hash5(a: Field, b: Field, c: Field, d: Field, e: Field) -> Field {
    bn254::hash_5([a, b, c, d, e])
}

/// Poseidon over 6 field elements (arity used by the note commitment).
pub fn hash6(a: Field, b: Field, c: Field, d: Field, e: Field, f: Field) -> Field {
    bn254::hash_6([a, b, c, d, e, f])
}
