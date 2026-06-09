//! The full Nightfall client transaction statement (transfer / withdraw / swap).
//!
//! Noir analogue of nf4's `unified_circuit.rs` (`assess_operation_integrity`).
//! It reproduces the complete statement — key derivation, mode detection, the
//! four commitments and nullifiers (with Merkle membership against the public
//! root), value/fee conservation, range checks, ownership, KEM-DEM encryption
//! with the withdraw override, the swap-link sponge, and the framed 27-word
//! public-input vector — with bit-for-bit parity against the real Nightfish
//! primitives (frozen in `../../vectors/statement.json`).
//!
//! Deposit mode (the SHA256 compression path) is intentionally out of scope:
//! `is_deposit` is asserted false, matching the transfer/withdraw/swap coverage
//! of the reference oracle.

use crate::bjj;
use crate::bjj::Point;
use crate::deposit;
use crate::domains::{DOMAIN_SHARED_SALT, PUBLIC_INPUTS_FRAMING, SWAP_DOMAIN};
use crate::hash;
use crate::kemdem;
use crate::keys;
use crate::merkle::{compute_root, PathElement};
use crate::note;
use crate::sponge;

/// Merkle membership-path depth (must match the deployed commitment-tree height).
pub global DEPTH: u32 = 32;
/// Number of framed words in the public-input vector.
pub global NUM_PUBLIC_INPUTS: u32 = 27;

/// Full private + public witness for the statement.
pub struct StatementInputs {
    // public
    pub root: Field,
    // key material
    pub root_key: Field,
    pub zkp_priv: Field,
    pub zkp_priv_lambda: Field,
    pub ephemeral_key: Field,
    // fee / addressing
    pub fee_token_id: Field,
    pub fee: Field,
    pub nf_address: Field,
    pub nf_slot_id: Field,
    // old (spent) notes
    pub nullifiers_values: [Field; 4],
    pub nullifiers_salts: [Field; 4],
    pub public_keys: [Point; 4],
    pub membership_proofs: [[PathElement; DEPTH]; 4],
    pub secret_preimages: [[Field; 3]; 4],
    // new notes
    pub commitments_values: [Field; 2],
    pub sender_commitment_salts: [Field; 3],
    // deposit slots (SHA256 mode)
    pub deposit_token_ids: [Field; 4],
    pub deposit_slot_ids: [Field; 4],
    pub deposit_values: [Field; 4],
    pub deposit_secret_hashes: [Field; 4],
    // withdraw
    pub withdraw_address: Field,
    // swap legs
    pub party_a_public_key: Point,
    pub party_b_public_key: Point,
    pub nf_token_a_id: Field,
    pub value_a: Field,
    pub nf_token_b_id: Field,
    pub value_b: Field,
    pub swap_nonce: Field,
    pub deadline: Field,
}

/// jf's `conditional_select(b, a, t)`: `a` when `b` is false, `t` when true.
fn cs(b: bool, a: Field, t: Field) -> Field {
    if b {
        t
    } else {
        a
    }
}

fn is_neutral(p: Point) -> bool {
    (p.x == 0) & (p.y == 1)
}

fn points_equal(a: Point, b: Point) -> bool {
    (a.x == b.x) & (a.y == b.y)
}

/// `is_lt(-x, x)` over the canonical integer representation.
fn x_parity(x: Field) -> Field {
    let neg_x = 0 - x;
    neg_x.lt(x) as Field
}

/// Run the full statement and return the framed public-input vector.
pub fn prove_statement(inp: StatementInputs) -> [Field; NUM_PUBLIC_INPUTS] {
    // --- range checks on addresses ---
    inp.withdraw_address.assert_max_bit_size::<160>();
    inp.nf_address.assert_max_bit_size::<160>();

    // --- key derivation (fail-closed) ---
    let zkp_priv = keys::derive_zkp_private_key(inp.root_key, inp.zkp_priv, inp.zkp_priv_lambda);
    let nullifier_key = keys::nullifier_key(inp.root_key);
    bjj::assert_valid_scalar(inp.ephemeral_key);
    let zkp_pub_key = bjj::mul_by_generator(zkp_priv);

    // --- mode detection ---
    let withdraw_flag = inp.withdraw_address != 0;
    let is_swap = inp.swap_nonce != 0;
    let is_deposit = inp.nullifiers_salts[0] == 0;

    // The ephemeral scalar is only consumed by the recipient encryption of a
    // genuine transfer. Deposits/withdrawals publish ephemeral-independent data,
    // so assert non-zero exactly when it is used, keeping the constraint tight.
    let encrypts_to_recipient = (!is_deposit) & (!withdraw_flag);
    if encrypts_to_recipient {
        assert(inp.ephemeral_key != 0, "statement: transfer ephemeral scalar is zero");
    }

    // --- role detection ---
    let is_party_a = points_equal(zkp_pub_key, inp.party_a_public_key);
    let is_party_b = points_equal(zkp_pub_key, inp.party_b_public_key);

    if !is_swap {
        assert(inp.nf_token_b_id == 0, "non-swap: nf_token_b_id must be 0");
        assert(inp.value_b == 0, "non-swap: value_b must be 0");
    }
    if (!is_swap) & (!is_deposit) {
        assert(is_party_a, "non-swap non-deposit: author must be party A");
    }

    // H2: canonical deposit/transfer mode exclusivity. The deposit-mode bit keys
    // solely off `nullifiers_salts[0] == 0`; pin the other mode's witnesses to
    // zero so a deposit cannot smuggle hidden spends/swap/withdraw state, and a
    // non-deposit cannot carry deposit witnesses.
    if is_deposit {
        for i in 1..4 {
            assert(inp.nullifiers_salts[i] == 0, "deposit: extra nullifier salt must be 0");
        }
        assert(inp.withdraw_address == 0, "deposit: withdraw_address must be 0");
        assert(inp.swap_nonce == 0, "deposit: swap_nonce must be 0");
    } else {
        for i in 0..4 {
            assert(inp.deposit_token_ids[i] == 0, "non-deposit: deposit token id must be 0");
            assert(inp.deposit_slot_ids[i] == 0, "non-deposit: deposit slot id must be 0");
            assert(inp.deposit_values[i] == 0, "non-deposit: deposit value must be 0");
            assert(inp.deposit_secret_hashes[i] == 0, "non-deposit: deposit secret hash must be 0");
        }
    }

    let is_party_b_swap = is_swap & is_party_b;
    let value = cs(is_party_b_swap, inp.value_a, inp.value_b);
    let nf_token_id = cs(is_party_b_swap, inp.nf_token_a_id, inp.nf_token_b_id);
    let recipient_public_key =
        if is_party_b_swap { inp.party_a_public_key } else { inp.party_b_public_key };

    // --- balance checks ---
    assert(
        value + inp.commitments_values[0]
            == inp.nullifiers_values[0] + inp.nullifiers_values[1],
        "balance: value + change != nullifier[0] + nullifier[1]",
    );
    assert(
        inp.fee + inp.commitments_values[1]
            == inp.nullifiers_values[2] + inp.nullifiers_values[3],
        "balance: fee + fee_change != fee_nullifier[0] + fee_nullifier[1]",
    );
    value.assert_max_bit_size::<96>();
    inp.fee.assert_max_bit_size::<96>();
    inp.commitments_values[0].assert_max_bit_size::<96>();
    inp.commitments_values[1].assert_max_bit_size::<96>();
    // H1: range-check every value that can enter the balance equation or be
    // committed, not just the outputs (dummy slots carry 0 and pass trivially).
    for i in 0..4 {
        inp.nullifiers_values[i].assert_max_bit_size::<96>();
        inp.deposit_values[i].assert_max_bit_size::<96>();
    }
    inp.value_a.assert_max_bit_size::<96>();
    inp.value_b.assert_max_bit_size::<96>();

    // --- ownership verification ---
    for i in 0..4 {
        let neutral = is_neutral(inp.public_keys[i]);
        let zero_value = inp.nullifiers_values[i] == 0;
        let skip = neutral | zero_value;
        let key_matches = points_equal(zkp_pub_key, inp.public_keys[i]);
        assert(skip | key_matches, "ownership: key mismatch");
    }

    // --- shared secret + commitment salt ---
    // M3: enforce on-curve + prime-subgroup membership of the DH base.
    bjj::assert_in_subgroup(recipient_public_key);
    let shared_secret = bjj::scalar_mul(inp.ephemeral_key, recipient_public_key);
    let epk = bjj::mul_by_generator(inp.ephemeral_key);
    bjj::assert_on_curve(shared_secret);
    bjj::assert_on_curve(epk);
    let shared_salt = hash::hash3(shared_secret.x, shared_secret.y, DOMAIN_SHARED_SALT);

    // --- commitments ---
    let commitments = verify_commitments(
        inp,
        nf_token_id,
        value,
        recipient_public_key,
        zkp_pub_key,
        shared_salt,
        withdraw_flag,
    );

    // --- nullifiers ---
    let nullifiers = verify_nullifiers(inp, nf_token_id, nullifier_key);

    // --- duplicates ---
    verify_duplicates(nullifiers, commitments);

    // --- encryption (with withdraw override) ---
    let compressed_secrets = verify_encryption(inp, nf_token_id, value, shared_secret, epk, withdraw_flag);

    // --- withdraw: recipient must be neutral ---
    if withdraw_flag {
        assert(is_neutral(recipient_public_key), "withdraw: recipient must be neutral");
    }

    // --- swap link + swap constraints ---
    let computed_swap_link = sponge::hash([
        SWAP_DOMAIN,
        inp.party_a_public_key.x,
        inp.party_a_public_key.y,
        inp.party_b_public_key.x,
        inp.party_b_public_key.y,
        inp.nf_token_a_id,
        inp.value_a,
        inp.nf_token_b_id,
        inp.value_b,
        inp.swap_nonce,
    ]);
    if is_swap {
        assert(!is_neutral(inp.party_a_public_key), "swap: party A neutral");
        assert(!is_neutral(inp.party_b_public_key), "swap: party B neutral");
        assert(!points_equal(inp.party_a_public_key, inp.party_b_public_key), "swap: parties equal");
        assert(is_party_a | is_party_b, "swap: author is neither party");
        assert(!withdraw_flag, "swap and withdraw mutually exclusive");
    }
    inp.swap_nonce.assert_max_bit_size::<64>();
    inp.deadline.assert_max_bit_size::<64>();
    if !is_swap {
        assert(inp.deadline == 0, "non-swap: deadline must be 0");
    }
    let final_swap_link = cs(is_swap, 0, computed_swap_link);

    // --- deposit mode (SHA256) ---
    // A slot is a real deposit unless its value and token id are both zero.
    // Real slots emit an arity-6 Poseidon commitment and a SHA256>>4 public-data
    // word; dummy slots emit 0. Selected in below when `is_deposit`.
    let mut deposit_commitments: [Field; 4] = [0; 4];
    let mut deposit_public_data: [Field; 5] = [0; 5];
    for i in 0..4 {
        let flag = !((inp.deposit_values[i] == 0) & (inp.deposit_token_ids[i] == 0));
        let chash = hash::hash6(
            inp.deposit_token_ids[i],
            inp.deposit_slot_ids[i],
            inp.deposit_values[i],
            0,
            1,
            inp.deposit_secret_hashes[i],
        );
        deposit_commitments[i] = cs(flag, 0, chash);
        let shifted = deposit::sha256_shift([
            inp.deposit_token_ids[i],
            inp.deposit_slot_ids[i],
            inp.deposit_values[i],
            inp.deposit_secret_hashes[i],
        ]);
        deposit_public_data[i] = cs(flag, 0, shifted);
    }
    // The fifth compressed-secret slot is a pushed zero in deposit mode.
    deposit_public_data[4] = 0;

    // --- public-input assembly (with deposit-mode selection) ---
    let final_fee = cs(is_deposit, inp.fee, 0);
    let final_root = cs(is_deposit, inp.root, 0);
    let out_swap_link = cs(is_deposit, final_swap_link, 0);
    let final_deadline = cs(is_deposit, cs(is_swap, 0, inp.deadline), 0);
    let final_side = cs(is_deposit, cs(is_swap, 0, is_party_a as Field), 0);

    let mut out_commitments: [Field; 4] = [0; 4];
    let mut out_nullifiers: [Field; 4] = [0; 4];
    for i in 0..4 {
        out_commitments[i] = cs(is_deposit, commitments[i], deposit_commitments[i]);
        out_nullifiers[i] = cs(is_deposit, nullifiers[i], 0);
    }
    let mut out_secrets: [Field; 5] = [0; 5];
    for i in 0..5 {
        out_secrets[i] = cs(is_deposit, compressed_secrets[i], deposit_public_data[i]);
    }

    [
        PUBLIC_INPUTS_FRAMING,
        1,
        final_fee,
        1,
        final_root,
        4,
        out_commitments[0],
        out_commitments[1],
        out_commitments[2],
        out_commitments[3],
        4,
        out_nullifiers[0],
        out_nullifiers[1],
        out_nullifiers[2],
        out_nullifiers[3],
        5,
        out_secrets[0],
        out_secrets[1],
        out_secrets[2],
        out_secrets[3],
        out_secrets[4],
        1,
        out_swap_link,
        1,
        final_deadline,
        1,
        final_side,
    ]
}

fn verify_commitments(
    inp: StatementInputs,
    nf_token_id: Field,
    value: Field,
    recipient: Point,
    sender: Point,
    shared_salt: Field,
    withdraw_flag: bool,
) -> [Field; 4] {
    let first_hash =
        note::commitment(nf_token_id, inp.nf_slot_id, value, recipient, shared_salt);
    let first = cs(withdraw_flag, first_hash, 0);

    let change0 = inp.commitments_values[0];
    let second_hash =
        note::commitment(nf_token_id, inp.nf_slot_id, change0, sender, inp.sender_commitment_salts[0]);
    let second = cs(change0 == 0, second_hash, 0);

    let third_hash = hash::hash6(
        inp.fee_token_id,
        inp.fee_token_id,
        inp.fee,
        0,
        inp.nf_address,
        inp.sender_commitment_salts[1],
    );
    let third = cs(inp.fee == 0, third_hash, 0);

    let change1 = inp.commitments_values[1];
    let fourth_hash =
        note::commitment(inp.fee_token_id, inp.fee_token_id, change1, sender, inp.sender_commitment_salts[2]);
    let fourth = cs(change1 == 0, fourth_hash, 0);

    [first, second, third, fourth]
}

fn verify_nullifiers(inp: StatementInputs, nf_token_id: Field, nullifier_key: Field) -> [Field; 4] {
    let mut out: [Field; 4] = [0; 4];
    for i in 0..4 {
        let salt = inp.nullifiers_salts[i];
        let is_zero = salt == 0;
        // C1: a dummy slot (salt == 0) skips Merkle membership and emits a zero
        // nullifier, so it must carry no value or it would mint into the balance.
        assert(cs(is_zero, 0, inp.nullifiers_values[i]) == 0, "nullifier: dummy slot must carry zero value");
        let t0 = if i < 2 { nf_token_id } else { inp.fee_token_id };
        let t1 = if i < 2 { inp.nf_slot_id } else { inp.fee_token_id };
        let commitment_hash = hash::hash6(
            t0,
            t1,
            inp.nullifiers_values[i],
            inp.public_keys[i].x,
            inp.public_keys[i].y,
            salt,
        );
        let deposit_key = note::deposit_nullifier_key(inp.secret_preimages[i]);
        let neutral = is_neutral(inp.public_keys[i]);
        let key_to_use = cs(neutral, nullifier_key, deposit_key);
        let nullifier = hash::hash2(key_to_use, commitment_hash);

        let calc_root = compute_root(commitment_hash, inp.membership_proofs[i]);
        let expected_root = cs(is_zero, inp.root, 0);
        let root_is_equal = calc_root == expected_root;
        let is_valid = if is_zero { true } else { root_is_equal };
        assert(is_valid, "nullifier: membership proof failed");
        out[i] = cs(is_zero, nullifier, 0);

        let secret_hash = hash::hash3(
            inp.secret_preimages[i][0],
            inp.secret_preimages[i][1],
            inp.secret_preimages[i][2],
        );
        let salt_to_enforce = cs(is_zero, cs(neutral, salt, secret_hash), 0);
        assert(salt_to_enforce == salt, "nullifier: salt-from-preimage");
    }
    out
}

fn verify_duplicates(nullifiers: [Field; 4], commitments: [Field; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            if i < j {
                assert((nullifiers[j] == 0) | (nullifiers[j] != nullifiers[i]), "duplicate nullifier");
                assert((commitments[j] == 0) | (commitments[j] != commitments[i]), "duplicate commitment");
            }
        }
    }
}

fn verify_encryption(
    inp: StatementInputs,
    nf_token_id: Field,
    value: Field,
    shared_secret: Point,
    epk: Point,
    withdraw_flag: bool,
) -> [Field; 5] {
    let enc_key = kemdem::derive_enc_key(shared_secret);
    let plains = [nf_token_id, inp.nf_slot_id, value];
    let ciphers = kemdem::dem_encrypt(enc_key, plains);
    let parity = x_parity(epk.x);
    let kem_dem = [ciphers[0], ciphers[1], ciphers[2], epk.y, parity];
    let withdraw_cipher = [nf_token_id, inp.withdraw_address, value, 0, 0];
    let mut out: [Field; 5] = [0; 5];
    for i in 0..5 {
        out[i] = cs(withdraw_flag, kem_dem[i], withdraw_cipher[i]);
    }
    out
}
