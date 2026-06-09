//! In-circuit parity & gadget tests (`nargo test`).
//!
//! These assert that the Noir gadgets reproduce the frozen Nightfish vectors
//! (produced by the real nf4 gadgets) bit-for-bit, plus self-consistency checks
//! for the curve, key derivation, and Merkle gadgets.

use crate::bjj;
use crate::client::{prove_client_tx, ClientInputs};
use crate::hash;
use crate::kemdem;
use crate::keys;
use crate::merkle::{assert_membership, compute_root, PathElement};
use crate::note;
use crate::vectors;

#[test]
fn generator_is_on_curve() {
    bjj::assert_on_curve(bjj::generator());
}

#[test]
fn zkp_private_key_derivation_matches_reference() {
    // Hash binds to root_key, and the witnessed reduction is enforced.
    let h = hash::hash2(vectors::IN_ROOT_KEY, crate::domains::PRIVATE_KEY_PREFIX);
    assert(h == vectors::OUT_ZKP_PRIV_HASH, "zkp_priv hash");

    let zkp_priv = keys::derive_zkp_private_key(
        vectors::IN_ROOT_KEY,
        vectors::OUT_ZKP_PRIV,
        vectors::OUT_ZKP_PRIV_LAMBDA,
    );
    assert(zkp_priv == vectors::OUT_ZKP_PRIV);
}

#[test(should_fail_with = "keys: zkp_priv derivation mismatch")]
fn zkp_private_key_rejects_wrong_witness() {
    // Wrong lambda must be rejected.
    let _ = keys::derive_zkp_private_key(vectors::IN_ROOT_KEY, vectors::OUT_ZKP_PRIV, 0);
}

#[test]
fn pk_matches_reference() {
    let pk = bjj::mul_by_generator(vectors::OUT_ZKP_PRIV);
    assert(pk.x == vectors::OUT_PK_X);
    assert(pk.y == vectors::OUT_PK_Y);
    bjj::assert_on_curve(pk);
}

#[test]
fn shared_secret_and_epk_match_reference() {
    let pk = bjj::Point { x: vectors::OUT_PK_X, y: vectors::OUT_PK_Y };
    let ss = bjj::scalar_mul(vectors::IN_EPHEMERAL, pk);
    assert(ss.x == vectors::OUT_SS_X);
    assert(ss.y == vectors::OUT_SS_Y);
    bjj::assert_on_curve(ss);

    let epk = bjj::mul_by_generator(vectors::IN_EPHEMERAL);
    assert(epk.x == vectors::OUT_EPK_X);
    assert(epk.y == vectors::OUT_EPK_Y);
    bjj::assert_on_curve(epk);
}

#[test]
fn kem_dem_matches_reference() {
    let ss = bjj::Point { x: vectors::OUT_SS_X, y: vectors::OUT_SS_Y };
    let enc_key = kemdem::derive_enc_key(ss);
    assert(enc_key == vectors::OUT_ENC_KEY);

    // Real plaintext: [nf_token_id, nf_slot_id, value].
    let plains = [vectors::IN_NF_TOKEN_ID, vectors::IN_NF_SLOT_ID, vectors::IN_VALUE];
    let ciphers = kemdem::dem_encrypt(enc_key, plains);
    assert(ciphers[0] == vectors::OUT_CIPHER0);
    assert(ciphers[1] == vectors::OUT_CIPHER1);
    assert(ciphers[2] == vectors::OUT_CIPHER2);

    // DEM round-trips.
    let recovered = kemdem::dem_decrypt(enc_key, ciphers);
    for i in 0..3 {
        assert(recovered[i] == plains[i]);
    }
}

#[test]
fn note_commitment_and_nullifier_match_reference() {
    let pk = bjj::Point { x: vectors::OUT_PK_X, y: vectors::OUT_PK_Y };
    let c = note::commitment(
        vectors::IN_NF_TOKEN_ID,
        vectors::IN_NF_SLOT_ID,
        vectors::IN_VALUE,
        pk,
        vectors::OUT_SALT,
    );
    assert(c == vectors::OUT_COMMITMENT);

    let nk = note::nullifier_key(vectors::IN_ROOT_KEY);
    assert(nk == vectors::OUT_NULL_KEY);

    let n = note::nullifier(vectors::IN_ROOT_KEY, c);
    assert(n == vectors::OUT_NULLIFIER);
}

#[test]
fn deposit_nullifier_key_matches_reference() {
    // Anchors the arity-4 Poseidon (hash6/hash4 coverage).
    let dnk = note::deposit_nullifier_key(vectors::IN_SECRET_PREIMAGE);
    assert(dnk == vectors::OUT_DEPOSIT_NULL_KEY);
}

#[test]
fn full_client_path_matches_reference() {
    let out = prove_client_tx(ClientInputs {
        root_key: vectors::IN_ROOT_KEY,
        zkp_priv: vectors::OUT_ZKP_PRIV,
        zkp_priv_lambda: vectors::OUT_ZKP_PRIV_LAMBDA,
        ephemeral: vectors::IN_EPHEMERAL,
        nf_token_id: vectors::IN_NF_TOKEN_ID,
        nf_slot_id: vectors::IN_NF_SLOT_ID,
        value: vectors::IN_VALUE,
        secret_preimage: vectors::IN_SECRET_PREIMAGE,
    });
    assert(out.commitment == vectors::OUT_COMMITMENT);
    assert(out.nullifier == vectors::OUT_NULLIFIER);
    assert(out.compressed_secrets[0] == vectors::OUT_CIPHER0);
    assert(out.compressed_secrets[1] == vectors::OUT_CIPHER1);
    assert(out.compressed_secrets[2] == vectors::OUT_CIPHER2);
    assert(out.compressed_secrets[3] == vectors::OUT_EPK_Y);
    assert(out.compressed_secrets[4] == vectors::OUT_X_PARITY);
    assert(out.deposit_null_key == vectors::OUT_DEPOSIT_NULL_KEY);
}

#[test(should_fail_with = "bjj: scalar out of subgroup range")]
fn rejects_scalar_at_subgroup_order() {
    bjj::assert_valid_scalar(bjj::SUBGROUP_ORDER);
}

#[test]
fn merkle_membership_roundtrip() {
    let leaf = 7;
    let s0 = 11;
    let s1 = 22;
    // leaf is the right child of s0; the level-1 node is the left child of s1.
    let level1 = hash::hash2(s0, leaf);
    let root = hash::hash2(level1, s1);

    let path = [
        PathElement { sibling: s0, sibling_on_left: true },
        PathElement { sibling: s1, sibling_on_left: false },
    ];

    assert(compute_root(leaf, path) == root);
    assert_membership(leaf, root, path);
}

#[test(should_fail_with = "merkle: membership proof failed")]
fn merkle_rejects_wrong_root() {
    let path = [PathElement { sibling: 11, sibling_on_left: true }];
    assert_membership(7, 12345, path);
}

// === Full-statement parity (transfer / withdraw / swap) ===

use crate::statement::prove_statement;
use crate::statement_v2::prove_statement_v2;
use crate::statement_vectors;
use crate::statement_v2_vectors;
use crate::sponge;

#[test]
fn sponge_one_chunk_equals_hash3() {
    // A single rate-3 chunk of the width-4 sponge equals the fixed Poseidon arity-3.
    assert(sponge::hash([11, 22, 33]) == hash::hash3(11, 22, 33));
}

#[test]
fn statement_transfer_matches_reference() {
    let (inp, expected) = statement_vectors::transfer();
    let got = prove_statement(inp);
    for i in 0..expected.len() {
        assert(got[i] == expected[i], "transfer public input mismatch");
    }
}

#[test]
fn statement_withdraw_matches_reference() {
    let (inp, expected) = statement_vectors::withdraw();
    let got = prove_statement(inp);
    for i in 0..expected.len() {
        assert(got[i] == expected[i], "withdraw public input mismatch");
    }
}

#[test]
fn statement_swap_matches_reference() {
    let (inp, expected) = statement_vectors::swap();
    let got = prove_statement(inp);
    for i in 0..expected.len() {
        assert(got[i] == expected[i], "swap public input mismatch");
    }
}

#[test]
fn statement_deposit_matches_reference() {
    let (inp, expected) = statement_vectors::deposit();
    let got = prove_statement(inp);
    for i in 0..expected.len() {
        assert(got[i] == expected[i], "deposit public input mismatch");
    }
}

#[test]
fn statement_v2_transfer_matches_reference() {
    let (inp, expected) = statement_v2_vectors::transfer();
    let got = prove_statement_v2(inp);
    for i in 0..expected.len() {
        assert(got[i] == expected[i], "statement_v2 public input mismatch");
    }
}
