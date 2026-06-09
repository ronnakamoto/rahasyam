//! Note commitment and nullifier (`nf4 lib/src/shared_entities.rs:377-435`,
//! `verify_commitments_gadgets.rs:51-58`, `verify_nullifiers_gadgets.rs:60-79`).
//!
//! - commitment = arity-6 `Poseidon(token_id, slot_id, value, pk.x, pk.y, salt)`
//! - nullifier  = `Poseidon(nullifier_key, commitment)`
//! - deposit nullifier key = arity-4 `Poseidon(sp0, sp1, sp2, DEPOSIT_NULLIFIER_DOMAIN)`

use crate::bjj::Point;
use crate::domains::DEPOSIT_NULLIFIER_DOMAIN;
use crate::hash;
use crate::keys;

/// Arity-6 note commitment binding a value to an owner public key.
pub fn commitment(token_id: Field, slot_id: Field, value: Field, pk: Point, salt: Field) -> Field {
    hash::hash6(token_id, slot_id, value, pk.x, pk.y, salt)
}

/// Re-export of the nullifier key derivation.
pub fn nullifier_key(root_key: Field) -> Field {
    keys::nullifier_key(root_key)
}

/// Compute the nullifier for a commitment owned by `root_key`.
pub fn nullifier(root_key: Field, commitment: Field) -> Field {
    hash::hash2(keys::nullifier_key(root_key), commitment)
}

/// Deposit nullifier key derived from a secret preimage (arity-4 Poseidon).
pub fn deposit_nullifier_key(secret_preimage: [Field; 3]) -> Field {
    hash::hash4(
        secret_preimage[0],
        secret_preimage[1],
        secret_preimage[2],
        DEPOSIT_NULLIFIER_DOMAIN,
    )
}
