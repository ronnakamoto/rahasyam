//! Key derivation from the root key (`nf4 lib/src/derive_key.rs`,
//! `unified_circuit.rs:111-150`).
//!
//! - `nullifier_key = Poseidon(root_key, NULLIFIER_PREFIX)`.
//! - `zkp_private_key = reduce(Poseidon(root_key, PRIVATE_KEY_PREFIX))` into the
//!   Baby JubJub scalar field. In-circuit the reduction is enforced with a
//!   witnessed quotient `lambda`: `hash == zkp_priv + lambda * l`, with
//!   `zkp_priv < l` and `lambda < 8` (mirrors nf4 exactly).

use crate::bjj;
use crate::domains::{NULLIFIER_PREFIX, PRIVATE_KEY_PREFIX};
use crate::hash;

/// M2: no-wrap bound for the BN254 -> Baby JubJub reduction, equal to
/// `FIELD_MODULUS - 7 * SUBGROUP_ORDER`. Because `8 * l > p` a malicious prover
/// could otherwise pick `lambda == 7` with a large `zkp_priv` so the integer sum
/// `zkp_priv + lambda * l` exceeds `p` and wraps to a different canonical hash.
/// Requiring `zkp_priv < NO_WRAP_BOUND` whenever `lambda == 7` keeps the integer
/// sum below `p`, making the reduction unique. (`lambda <= 6` cannot wrap since
/// `7 * l - 1 < p`.)
global NO_WRAP_BOUND: Field =
    2736030358979909402780800718157159386010666595306063529296694559936676884330;

/// Derive the nullifier key from the owner's root key.
pub fn nullifier_key(root_key: Field) -> Field {
    hash::hash2(root_key, NULLIFIER_PREFIX)
}

/// Derive and constrain the zkp private key.
///
/// `zkp_priv` and `lambda` are witnessed; this enforces they are the unique
/// reduction of `Poseidon(root_key, PRIVATE_KEY_PREFIX)` modulo the Baby JubJub
/// subgroup order. Returns the constrained `zkp_priv`.
pub fn derive_zkp_private_key(root_key: Field, zkp_priv: Field, lambda: Field) -> Field {
    let h = hash::hash2(root_key, PRIVATE_KEY_PREFIX);
    assert(zkp_priv + lambda * bjj::SUBGROUP_ORDER == h, "keys: zkp_priv derivation mismatch");
    assert(zkp_priv.lt(bjj::SUBGROUP_ORDER), "keys: zkp_priv >= subgroup order");
    assert(lambda.lt(8), "keys: reduction quotient out of range");
    assert(zkp_priv != 0, "keys: zkp_priv is zero");
    // M2: no-wrap guard. Only `lambda == 7` can wrap the field modulus; in that
    // case require `zkp_priv < NO_WRAP_BOUND`. For other lambda the guarded value
    // is 0, which is trivially within bound.
    let guarded = if lambda == 7 { zkp_priv } else { 0 };
    assert(guarded.lt(NO_WRAP_BOUND), "keys: zkp_priv reduction wraps the field modulus");
    zkp_priv
}
