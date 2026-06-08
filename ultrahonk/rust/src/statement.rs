//! The full Nightfall client transaction statement (transfer / withdraw / swap).
//!
//! This is the native reference oracle for nf4's `unified_circuit.rs`
//! (`assess_operation_integrity`). It reproduces — with the real `nf_curves` +
//! `jf_primitives` primitives — the complete statement:
//!
//! - key derivation (`zkp_private_key`, `nullifier_key`) with the BN254→BJJ
//!   reduction witness (`unified_circuit.rs:111-154`);
//! - mode detection (`withdraw` / `deposit` / `swap`) and swap role/value/token
//!   selection (`:156-213`);
//! - value/fee conservation + 96-bit range checks (`:215-253`);
//! - per-slot ownership verification (`:255-280`);
//! - the four commitments (`verify_commitments_gadgets.rs`) — recipient note,
//!   transfer change, fee, fee change — with conditional zeroing;
//! - the four nullifiers (`verify_nullifiers_gadgets.rs`) — neutral→`nullifier_key`
//!   vs deposit→`Poseidon(secret_preimage, DEPOSIT_NULLIFIER_V1)`, Merkle
//!   membership against the public `root`, and salt-from-preimage;
//! - the duplicates check (`verify_duplicates_gadgets.rs`);
//! - KEM-DEM encryption with the withdraw ciphertext override
//!   (`verify_encryption_gadgets.rs`);
//! - the `swap_link` Poseidon sponge (`:282-328`);
//! - the framed 25-word public-input vector (`:439-563`,
//!   `nf_client_proof.rs:159-184`).
//!
//! Everything is **fail-closed**: any violated constraint panics in the oracle,
//! exactly as it would abort witness generation in-circuit.

use crate::{bjj, domains, kemdem, keys, merkle, poseidon, sponge, Point};
use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use nf_curves::ed_on_bn254::Fr as BjjFr;

/// jf's `conditional_select(b, a, t)`: returns `a` when `b == false`, `t` when
/// `b == true` (i.e. `b ? t : a`). See `verify_commitments_gadgets.rs:59-60`.
fn cs(b: bool, a: Fr254, t: Fr254) -> Fr254 {
    if b {
        t
    } else {
        a
    }
}

/// The neutral Baby JubJub point `(0, 1)`.
fn is_neutral(p: &Point) -> bool {
    p.x.is_zero() && p.y.is_one()
}

fn points_equal(a: &Point, b: &Point) -> bool {
    a.x == b.x && a.y == b.y
}

/// `is_lt(-x, x)` over the canonical integer representation
/// (`verify_encryption_gadgets.rs:37-44`).
fn x_parity_flag(x: Fr254) -> Fr254 {
    if (-x).into_bigint() < x.into_bigint() {
        Fr254::one()
    } else {
        Fr254::zero()
    }
}

fn assert_max_bits(v: Fr254, bits: u32, name: &str) {
    let limit = num_bigint::BigUint::from(1u8) << bits;
    let val = num_bigint::BigUint::from_bytes_be(&v.into_bigint().to_bytes_be());
    assert!(val < limit, "{name} exceeds {bits} bits");
}

/// Full private + public witness for the statement.
#[derive(Clone, Debug)]
pub struct StatementInputs {
    // --- public scalars ---
    /// Public commitment-tree root the spent notes are proved against.
    pub root: Fr254,
    // --- key material ---
    /// Root key (`zkp_private_key` and `nullifier_key` are derived from it).
    pub root_key: Fr254,
    /// Ephemeral KEM scalar.
    pub ephemeral_key: BjjFr,
    // --- fee / addressing ---
    pub fee_token_id: Fr254,
    pub fee: Fr254,
    /// Nightfall L2 address that receives the fee commitment.
    pub nf_address: Fr254,
    pub nf_slot_id: Fr254,
    // --- old (spent) notes ---
    pub nullifiers_values: [Fr254; 4],
    pub nullifiers_salts: [Fr254; 4],
    /// Owner public key of each spent note.
    pub public_keys: [Point; 4],
    /// Membership path of each spent note's commitment.
    pub membership_proofs: [Vec<merkle::PathElement>; 4],
    /// Per-slot secret preimage (deposit nullifier key + salt-from-preimage).
    pub secret_preimages: [[Fr254; 3]; 4],
    // --- new notes ---
    /// `[transfer_change_value, fee_change_value]`.
    pub commitments_values: [Fr254; 2],
    /// Salts for `[transfer_change, fee, fee_change]`.
    pub sender_commitment_salts: [Fr254; 3],
    // --- deposit slots (SHA256 mode) ---
    /// Per-slot deposit token id; a slot is a real deposit unless its value and
    /// token id are both zero (`DepositDataVar::is_real`).
    pub deposit_token_ids: [Fr254; 4],
    pub deposit_slot_ids: [Fr254; 4],
    pub deposit_values: [Fr254; 4],
    /// `secret_hash` of each deposit slot (commitment + SHA256 public data).
    pub deposit_secret_hashes: [Fr254; 4],
    // --- withdraw ---
    pub withdraw_address: Fr254,
    // --- swap legs ---
    pub party_a_public_key: Point,
    pub party_b_public_key: Point,
    pub nf_token_a_id: Fr254,
    pub value_a: Fr254,
    pub nf_token_b_id: Fr254,
    pub value_b: Fr254,
    pub swap_nonce: Fr254,
    pub deadline: Fr254,
}

/// Full output trace of the statement.
#[derive(Clone, Debug)]
pub struct StatementTrace {
    // mode flags
    pub withdraw_flag: bool,
    pub is_swap: bool,
    pub is_deposit: bool,
    pub is_party_a: bool,
    // key derivation witnesses
    pub zkp_priv: BjjFr,
    pub zkp_priv_hash: Fr254,
    pub zkp_priv_lambda: Fr254,
    pub zkp_pub_key: Point,
    pub nullifier_key: Fr254,
    // derived spend values
    pub value: Fr254,
    pub nf_token_id: Fr254,
    pub recipient_public_key: Point,
    pub shared_secret: Point,
    pub epk: Point,
    pub shared_salt: Fr254,
    // public outputs
    pub commitments: [Fr254; 4],
    pub nullifiers: [Fr254; 4],
    pub compressed_secrets: [Fr254; 5],
    pub swap_link: Fr254,
    pub final_fee: Fr254,
    pub final_root: Fr254,
    pub final_deadline: Fr254,
    pub swap_side: Fr254,
    /// The framed 25-word public-input vector.
    pub public_inputs: Vec<Fr254>,
}

/// Run the full statement, enforcing every constraint (fail-closed), and return
/// the trace + public-input vector.
pub fn compute_statement(inp: &StatementInputs) -> StatementTrace {
    // --- range checks on addresses ---
    assert_max_bits(inp.withdraw_address, 160, "withdraw_address");
    assert_max_bits(inp.nf_address, 160, "nf_address");

    // --- key derivation ---
    let (zkp_priv, zkp_priv_hash, zkp_priv_lambda) =
        keys::zkp_private_key_witness(inp.root_key);
    assert!(!zkp_priv.is_zero(), "derived zkp_private_key is zero");
    let nullifier_key = keys::nullifier_key(inp.root_key);
    let zkp_pub_key = bjj::mul_by_generator(zkp_priv);

    // --- mode detection ---
    let withdraw_flag = !inp.withdraw_address.is_zero();
    let is_swap = !inp.swap_nonce.is_zero();
    let is_deposit = inp.nullifiers_salts[0].is_zero();

    // --- role detection ---
    let is_party_a = points_equal(&zkp_pub_key, &inp.party_a_public_key);
    let is_party_b = points_equal(&zkp_pub_key, &inp.party_b_public_key);

    // Non-swap canonicalisation: token_b / value_b must be zero.
    if !is_swap {
        assert!(inp.nf_token_b_id.is_zero(), "non-swap: nf_token_b_id must be 0");
        assert!(inp.value_b.is_zero(), "non-swap: value_b must be 0");
    }
    // Non-swap, non-deposit transactions must be authored by party A.
    if !is_swap && !is_deposit {
        assert!(is_party_a, "non-swap non-deposit: author must be party A");
    }

    let is_party_b_swap = is_swap && is_party_b;
    let value = cs(is_party_b_swap, inp.value_a, inp.value_b);
    let nf_token_id = cs(is_party_b_swap, inp.nf_token_a_id, inp.nf_token_b_id);
    let recipient_public_key = if is_party_b_swap {
        inp.party_a_public_key
    } else {
        inp.party_b_public_key
    };

    // --- balance checks ---
    assert_eq!(
        value + inp.commitments_values[0],
        inp.nullifiers_values[0] + inp.nullifiers_values[1],
        "value + change != nullifier[0] + nullifier[1]"
    );
    assert_eq!(
        inp.fee + inp.commitments_values[1],
        inp.nullifiers_values[2] + inp.nullifiers_values[3],
        "fee + fee_change != fee_nullifier[0] + fee_nullifier[1]"
    );
    assert_max_bits(value, 96, "value");
    assert_max_bits(inp.fee, 96, "fee");
    assert_max_bits(inp.commitments_values[0], 96, "transfer_change");
    assert_max_bits(inp.commitments_values[1], 96, "fee_change");

    // --- ownership verification ---
    for i in 0..4 {
        let neutral = is_neutral(&inp.public_keys[i]);
        let zero_value = inp.nullifiers_values[i].is_zero();
        let skip = neutral || zero_value;
        let key_matches = points_equal(&zkp_pub_key, &inp.public_keys[i]);
        assert!(skip || key_matches, "ownership: slot {i} key mismatch");
    }

    // --- shared secret + commitment salt ---
    let shared_secret = bjj::scalar_mul(inp.ephemeral_key, recipient_public_key);
    let epk = bjj::mul_by_generator(inp.ephemeral_key);
    let shared_salt =
        poseidon::hash(&[shared_secret.x, shared_secret.y, domains::domain_shared_salt()]);

    // --- commitments (verify_commitments) ---
    let commitments = verify_commitments(inp, nf_token_id, value, &recipient_public_key, &zkp_pub_key, shared_salt, withdraw_flag);

    // --- nullifiers (verify_nullifiers) ---
    let nullifiers = verify_nullifiers(inp, nf_token_id, nullifier_key);

    // --- duplicates ---
    verify_duplicates(&nullifiers, &commitments);

    // --- encryption (verify_encryption with withdraw override) ---
    let compressed_secrets = verify_encryption(inp, nf_token_id, value, &shared_secret, &epk, withdraw_flag);

    // --- withdraw: recipient must be neutral ---
    if withdraw_flag {
        assert!(is_neutral(&recipient_public_key), "withdraw: recipient must be neutral");
    }

    // --- swap link + swap constraints ---
    let computed_swap_link = sponge::hash(&[
        domains::swap_domain(),
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
        assert!(!is_neutral(&inp.party_a_public_key), "swap: party A neutral");
        assert!(!is_neutral(&inp.party_b_public_key), "swap: party B neutral");
        assert!(
            !points_equal(&inp.party_a_public_key, &inp.party_b_public_key),
            "swap: parties must differ"
        );
        assert!(is_party_a || is_party_b, "swap: author is neither party");
        assert!(!withdraw_flag, "swap and withdraw are mutually exclusive");
    }
    assert_max_bits(inp.swap_nonce, 64, "swap_nonce");
    assert_max_bits(inp.deadline, 64, "deadline");
    if !is_swap {
        assert!(inp.deadline.is_zero(), "non-swap: deadline must be 0");
    }
    let final_swap_link = cs(is_swap, Fr254::zero(), computed_swap_link);

    // --- deposit mode (SHA256) ---
    // A slot is a real deposit unless both its value and token id are zero
    // (`DepositDataVar::is_real`). Real slots contribute an arity-6 Poseidon
    // commitment and a SHA256>>4 public-data word; dummy slots contribute 0.
    let deposit_flags: [bool; 4] = std::array::from_fn(|i| {
        !(inp.deposit_values[i].is_zero() && inp.deposit_token_ids[i].is_zero())
    });
    let deposit_commitments: [Fr254; 4] = std::array::from_fn(|i| {
        let h = poseidon::hash(&[
            inp.deposit_token_ids[i],
            inp.deposit_slot_ids[i],
            inp.deposit_values[i],
            Fr254::zero(),
            Fr254::one(),
            inp.deposit_secret_hashes[i],
        ]);
        // `to_commitment`: conditional_select(flag, 0, hash) == flag ? hash : 0.
        cs(deposit_flags[i], Fr254::zero(), h)
    });
    let deposit_public_data: [Fr254; 5] = {
        let mut pd = [Fr254::zero(); 5];
        for i in 0..4 {
            let s = crate::deposit::sha256_shift(&[
                inp.deposit_token_ids[i],
                inp.deposit_slot_ids[i],
                inp.deposit_values[i],
                inp.deposit_secret_hashes[i],
            ]);
            // `sha256_and_shift`: conditional_select(flag, 0, s) == flag ? s : 0.
            pd[i] = cs(deposit_flags[i], Fr254::zero(), s);
        }
        // The fifth compressed-secret slot is a pushed zero in deposit mode.
        pd[4] = Fr254::zero();
        pd
    };

    // --- public-input assembly (with deposit-mode selection) ---
    let final_fee = cs(is_deposit, inp.fee, Fr254::zero());
    let final_root = cs(is_deposit, inp.root, Fr254::zero());
    // Deposit mode swaps in the SHA256 commitments / public data and zeroes the
    // nullifiers; non-deposit modes expose the real transfer/withdraw/swap values.
    let out_commitments: [Fr254; 4] =
        std::array::from_fn(|i| cs(is_deposit, commitments[i], deposit_commitments[i]));
    let out_nullifiers: [Fr254; 4] =
        std::array::from_fn(|i| cs(is_deposit, nullifiers[i], Fr254::zero()));
    let out_secrets: [Fr254; 5] =
        std::array::from_fn(|i| cs(is_deposit, compressed_secrets[i], deposit_public_data[i]));
    let out_swap_link = cs(is_deposit, final_swap_link, Fr254::zero());
    let final_deadline = cs(is_swap, Fr254::zero(), inp.deadline);
    let final_deadline = cs(is_deposit, final_deadline, Fr254::zero());
    let final_side = cs(is_swap, Fr254::zero(), if is_party_a { Fr254::one() } else { Fr254::zero() });
    let swap_side = cs(is_deposit, final_side, Fr254::zero());

    let one = Fr254::one();
    let four = Fr254::from(4u8);
    let five = Fr254::from(5u8);
    let mut public_inputs = vec![domains::public_inputs_framing()];
    public_inputs.push(one);
    public_inputs.push(final_fee);
    public_inputs.push(one);
    public_inputs.push(final_root);
    public_inputs.push(four);
    public_inputs.extend_from_slice(&out_commitments);
    public_inputs.push(four);
    public_inputs.extend_from_slice(&out_nullifiers);
    public_inputs.push(five);
    public_inputs.extend_from_slice(&out_secrets);
    public_inputs.push(one);
    public_inputs.push(out_swap_link);
    public_inputs.push(one);
    public_inputs.push(final_deadline);
    public_inputs.push(one);
    public_inputs.push(swap_side);

    StatementTrace {
        withdraw_flag,
        is_swap,
        is_deposit,
        is_party_a,
        zkp_priv,
        zkp_priv_hash,
        zkp_priv_lambda,
        zkp_pub_key,
        nullifier_key,
        value,
        nf_token_id,
        recipient_public_key,
        shared_secret,
        epk,
        shared_salt,
        commitments: out_commitments,
        nullifiers: out_nullifiers,
        compressed_secrets: out_secrets,
        swap_link: out_swap_link,
        final_fee,
        final_root,
        final_deadline,
        swap_side,
        public_inputs,
    }
}

fn verify_commitments(
    inp: &StatementInputs,
    nf_token_id: Fr254,
    value: Fr254,
    recipient: &Point,
    sender: &Point,
    shared_salt: Fr254,
    withdraw_flag: bool,
) -> [Fr254; 4] {
    let first_hash = poseidon::hash(&[
        nf_token_id,
        inp.nf_slot_id,
        value,
        recipient.x,
        recipient.y,
        shared_salt,
    ]);
    let first = cs(withdraw_flag, first_hash, Fr254::zero());

    let change0 = inp.commitments_values[0];
    let second_hash = poseidon::hash(&[
        nf_token_id,
        inp.nf_slot_id,
        change0,
        sender.x,
        sender.y,
        inp.sender_commitment_salts[0],
    ]);
    let second = cs(change0.is_zero(), second_hash, Fr254::zero());

    let third_hash = poseidon::hash(&[
        inp.fee_token_id,
        inp.fee_token_id,
        inp.fee,
        Fr254::zero(),
        inp.nf_address,
        inp.sender_commitment_salts[1],
    ]);
    let third = cs(inp.fee.is_zero(), third_hash, Fr254::zero());

    let change1 = inp.commitments_values[1];
    let fourth_hash = poseidon::hash(&[
        inp.fee_token_id,
        inp.fee_token_id,
        change1,
        sender.x,
        sender.y,
        inp.sender_commitment_salts[2],
    ]);
    let fourth = cs(change1.is_zero(), fourth_hash, Fr254::zero());

    [first, second, third, fourth]
}

fn verify_nullifiers(inp: &StatementInputs, nf_token_id: Fr254, nullifier_key: Fr254) -> [Fr254; 4] {
    let deposit_domain = domains::deposit_nullifier_domain();
    let mut out = [Fr254::zero(); 4];
    for i in 0..4 {
        let salt = inp.nullifiers_salts[i];
        let is_zero = salt.is_zero();
        let (t0, t1) = if i < 2 {
            (nf_token_id, inp.nf_slot_id)
        } else {
            (inp.fee_token_id, inp.fee_token_id)
        };
        let commitment_hash = poseidon::hash(&[
            t0,
            t1,
            inp.nullifiers_values[i],
            inp.public_keys[i].x,
            inp.public_keys[i].y,
            salt,
        ]);
        let deposit_key = poseidon::hash(&[
            inp.secret_preimages[i][0],
            inp.secret_preimages[i][1],
            inp.secret_preimages[i][2],
            deposit_domain,
        ]);
        let neutral = is_neutral(&inp.public_keys[i]);
        let key_to_use = cs(neutral, nullifier_key, deposit_key);
        let nullifier = poseidon::hash(&[key_to_use, commitment_hash]);

        // Merkle membership against the public root (only enforced for spent notes).
        let calc_root = merkle::compute_root(commitment_hash, &inp.membership_proofs[i]);
        let expected_root = cs(is_zero, inp.root, Fr254::zero());
        let root_is_equal = calc_root == expected_root;
        let is_valid = if is_zero { true } else { root_is_equal };
        assert!(is_valid, "nullifier slot {i}: membership proof failed");
        out[i] = cs(is_zero, nullifier, Fr254::zero());

        // Salt must come from the secret preimage when the owner key is neutral.
        let secret_hash = poseidon::hash(&inp.secret_preimages[i]);
        let salt_to_enforce = cs(neutral, salt, secret_hash);
        let salt_to_enforce = cs(is_zero, salt_to_enforce, Fr254::zero());
        assert_eq!(salt_to_enforce, salt, "nullifier slot {}: salt-from-preimage", i);
    }
    out
}

fn verify_duplicates(nullifiers: &[Fr254; 4], commitments: &[Fr254; 4]) {
    for arr in [nullifiers, commitments] {
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert!(
                    arr[j].is_zero() || arr[j] != arr[i],
                    "duplicate non-zero entry"
                );
            }
        }
    }
}

fn verify_encryption(
    inp: &StatementInputs,
    nf_token_id: Fr254,
    value: Fr254,
    shared_secret: &Point,
    epk: &Point,
    withdraw_flag: bool,
) -> [Fr254; 5] {
    let enc_key = kemdem::derive_enc_key(shared_secret);
    let plains = [nf_token_id, inp.nf_slot_id, value];
    let ciphers = kemdem::dem_encrypt(enc_key, &plains);
    let parity = x_parity_flag(epk.x);
    let kem_dem = [ciphers[0], ciphers[1], ciphers[2], epk.y, parity];
    let withdraw_cipher = [
        nf_token_id,
        inp.withdraw_address,
        value,
        Fr254::zero(),
        Fr254::zero(),
    ];
    let mut out = [Fr254::zero(); 5];
    for i in 0..5 {
        out[i] = cs(withdraw_flag, kem_dem[i], withdraw_cipher[i]);
    }
    out
}

/// Canonical transfer / withdraw / swap scenarios.
///
/// These are the single source of truth for the frozen vectors
/// (`examples/gen_statement.rs`), the circuit `Prover.toml`, the Noir fixtures
/// (`noir/src/statement_vectors.nr`), and the Rust parity tests. Keeping them in
/// the library guarantees the generator and the tests exercise identical inputs.
pub mod scenarios {
    use super::StatementInputs;
    use crate::{bjj, keys, merkle::PathElement, poseidon, Point};
    use ark_bn254::Fr as Fr254;
    use ark_ff::{One, Zero};
    use nf_curves::ed_on_bn254::Fr as BjjFr;

    /// Merkle path depth used by the reference vectors + provable circuit.
    /// Production must match the deployed commitment-tree height.
    pub const DEPTH: usize = 32;

    fn fr(n: u64) -> Fr254 {
        Fr254::from(n)
    }

    /// The neutral Baby JubJub point `(0, 1)`.
    pub fn neutral() -> Point {
        Point::new_unchecked(Fr254::zero(), Fr254::one())
    }

    /// Public key derived from a root key, exactly as the statement derives the
    /// owner's `zkp_pub_key`.
    pub fn pk_from_root(root_key: u64) -> Point {
        bjj::mul_by_generator(keys::zkp_private_key(fr(root_key)))
    }

    /// A zero-sibling path of length [`DEPTH`] (leaf at index 0).
    pub fn zero_path() -> Vec<PathElement> {
        vec![
            PathElement {
                sibling: Fr254::zero(),
                sibling_on_left: false,
            };
            DEPTH
        ]
    }

    /// Base inputs: everything padded/zeroed; scenarios override specific fields.
    pub fn base_inputs() -> StatementInputs {
        StatementInputs {
            root: Fr254::zero(),
            root_key: fr(31337),
            ephemeral_key: BjjFr::from(555555u64),
            fee_token_id: fr(9),
            fee: Fr254::zero(),
            nf_address: Fr254::zero(),
            nf_slot_id: fr(3),
            nullifiers_values: [Fr254::zero(); 4],
            nullifiers_salts: [Fr254::zero(); 4],
            public_keys: [neutral(), neutral(), neutral(), neutral()],
            membership_proofs: [zero_path(), zero_path(), zero_path(), zero_path()],
            secret_preimages: [[Fr254::zero(); 3]; 4],
            commitments_values: [Fr254::zero(); 2],
            sender_commitment_salts: [Fr254::zero(); 3],
            deposit_token_ids: [Fr254::zero(); 4],
            deposit_slot_ids: [Fr254::zero(); 4],
            deposit_values: [Fr254::zero(); 4],
            deposit_secret_hashes: [Fr254::zero(); 4],
            withdraw_address: Fr254::zero(),
            party_a_public_key: neutral(),
            party_b_public_key: neutral(),
            nf_token_a_id: fr(7),
            value_a: Fr254::zero(),
            nf_token_b_id: Fr254::zero(),
            value_b: Fr254::zero(),
            swap_nonce: Fr254::zero(),
            deadline: Fr254::zero(),
        }
    }

    /// Compute the slot-0 commitment hash and set `root` to a matching
    /// membership root, so the spent note is provably in the tree.
    fn anchor_root_to_slot0(inp: &mut StatementInputs, token0: Fr254) {
        let pk = inp.public_keys[0];
        let commitment_hash = poseidon::hash(&[
            token0,
            inp.nf_slot_id,
            inp.nullifiers_values[0],
            pk.x,
            pk.y,
            inp.nullifiers_salts[0],
        ]);
        inp.root = merkle::compute_root(commitment_hash, &inp.membership_proofs[0]);
    }
    use crate::merkle;

    pub fn transfer_inputs() -> StatementInputs {
        let mut inp = base_inputs();
        let sender = pk_from_root(31337);
        let recipient = pk_from_root(42);
        inp.party_a_public_key = sender;
        inp.party_b_public_key = recipient;
        inp.value_a = fr(600);
        inp.commitments_values = [fr(400), Fr254::zero()];
        inp.nullifiers_values = [fr(1000), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.nullifiers_salts = [fr(12345), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.public_keys[0] = sender;
        inp.secret_preimages[0] = [fr(11), fr(22), fr(33)];
        inp.sender_commitment_salts = [fr(777), Fr254::zero(), Fr254::zero()];
        let token0 = inp.nf_token_a_id;
        anchor_root_to_slot0(&mut inp, token0);
        inp
    }

    pub fn withdraw_inputs() -> StatementInputs {
        let mut inp = base_inputs();
        let sender = pk_from_root(31337);
        inp.party_a_public_key = sender;
        inp.party_b_public_key = neutral(); // withdraw recipient must be neutral
        inp.withdraw_address = fr(0x00FF_EE11);
        inp.value_a = fr(600);
        inp.commitments_values = [fr(400), Fr254::zero()];
        inp.nullifiers_values = [fr(1000), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.nullifiers_salts = [fr(12345), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.public_keys[0] = sender;
        inp.secret_preimages[0] = [fr(11), fr(22), fr(33)];
        inp.sender_commitment_salts = [fr(777), Fr254::zero(), Fr254::zero()];
        let token0 = inp.nf_token_a_id;
        anchor_root_to_slot0(&mut inp, token0);
        inp
    }

    pub fn swap_inputs() -> StatementInputs {
        let mut inp = base_inputs();
        let party_a = pk_from_root(31337);
        let party_b = pk_from_root(42);
        inp.party_a_public_key = party_a;
        inp.party_b_public_key = party_b;
        inp.nf_token_a_id = fr(7);
        inp.value_a = fr(600);
        inp.nf_token_b_id = fr(8);
        inp.value_b = fr(900);
        inp.swap_nonce = fr(123456);
        inp.deadline = fr(1_700_000_000);
        inp.commitments_values = [fr(400), Fr254::zero()];
        inp.nullifiers_values = [fr(1000), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.nullifiers_salts = [fr(12345), Fr254::zero(), Fr254::zero(), Fr254::zero()];
        inp.public_keys[0] = party_a;
        inp.secret_preimages[0] = [fr(11), fr(22), fr(33)];
        inp.sender_commitment_salts = [fr(777), Fr254::zero(), Fr254::zero()];
        let token0 = inp.nf_token_a_id;
        anchor_root_to_slot0(&mut inp, token0);
        inp
    }

    /// A deposit (SHA256 mode). Determined by `nullifiers_salts[0] == 0`: nothing
    /// is spent (all nullifier slots dummy), and one real deposit slot creates a
    /// new commitment + SHA256 public-data word. `root`/`fee` stay zero.
    pub fn deposit_inputs() -> StatementInputs {
        let mut inp = base_inputs();
        // No spends: all nullifier salts/values zero ⇒ is_deposit, ownership skipped.
        // Non-swap, non-withdraw: token_b/value_b/deadline/withdraw_address all zero.
        // Two real deposit slots, two dummy (value & token both zero).
        inp.deposit_token_ids = [fr(7), fr(8), Fr254::zero(), Fr254::zero()];
        inp.deposit_slot_ids = [fr(3), fr(5), Fr254::zero(), Fr254::zero()];
        inp.deposit_values = [fr(1000), fr(250), Fr254::zero(), Fr254::zero()];
        inp.deposit_secret_hashes = [fr(424242), fr(99), Fr254::zero(), Fr254::zero()];
        inp
    }
}
