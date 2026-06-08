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
    zkp_priv
}
