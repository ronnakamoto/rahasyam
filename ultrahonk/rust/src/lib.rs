//! # nightfish-honk-ref
//!
//! Native **reference oracle** for the `nightfish-honk` Noir library.
//!
//! It computes the Nightfall client crypto path using the *real* Nightfish
//! primitives — `nf_curves::ed_on_bn254` (Baby JubJub, `a = 1`) and
//! `jf_primitives::Poseidon` — so that the Noir circuit can be validated
//! bit-for-bit against it. The output of [`compute_client`] is the single source
//! of truth frozen into `../vectors/client_ref.json`, `../noir/src/vectors.nr`,
//! and the `tests/parity.rs` assertions here.
//!
//! The formulas reproduced here are nf4's **real** gadgets (not a simplification):
//! - `zkp_private_key = from_be_bytes_mod_order(Poseidon(root_key, PRIVATE_KEY_PREFIX))`
//!   reduced into the Baby JubJub scalar field
//!   (`nf4 lib/src/derive_key.rs:121-150`).
//! - `nullifier_key = Poseidon(root_key, NULLIFIER_PREFIX)`
//!   (`nf4 lib/src/derive_key.rs:124-135`).
//! - note commitment = arity-6 `Poseidon(token_id, slot_id, value, pk.x, pk.y, salt)`
//!   (`nf4 lib/src/shared_entities.rs:377-388`,
//!   `verify_commitments_gadgets.rs:51-58`).
//! - nullifier = `Poseidon(nullifier_key, commitment)`
//!   (`verify_nullifiers_gadgets.rs:60-79`).
//! - deposit nullifier key = arity-4 `Poseidon(sp0, sp1, sp2, DEPOSIT_NULLIFIER_V1)`
//!   (`verify_nullifiers_gadgets.rs:16-18,70-75`).
//! - KEM-DEM over plaintext `[nf_token_id, nf_slot_id, value]`:
//!   `enc_key = Poseidon(ss.x, ss.y, DOMAIN_KEM)`,
//!   `cipher_i = Poseidon(enc_key, DOMAIN_DEM, i) + plain_i`,
//!   packed as `compressed_secrets = [c0, c1, c2, epk.y, x_parity]`
//!   (`kemdem_gadgets.rs:31-60`, `verify_encryption_gadgets.rs:31-50`).
//!
//! There are deliberately **no fallbacks**: a hashing or curve error is surfaced
//! as a panic in the reference path, never silently masked.

use ark_bn254::Fr as Fr254;
use ark_ec::{twisted_edwards::Affine as TEAffine, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use jf_primitives::poseidon::{FieldHasher, Poseidon};
use nf_curves::ed_on_bn254::{BabyJubjub, Fr as BjjFr};

/// An affine Baby JubJub point over `ed_on_bn254`.
pub type Point = TEAffine<BabyJubjub>;

/// Parse a decimal string into a BN254 scalar-field element.
pub fn fr_from_dec(s: &str) -> Fr254 {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10)
        .unwrap_or_else(|| panic!("invalid decimal field element: {s}"));
    Fr254::from_le_bytes_mod_order(&n.to_bytes_le())
}

/// Format a BN254 scalar-field element as a decimal string.
pub fn fr_to_dec(f: &Fr254) -> String {
    num_bigint::BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
}

/// Format a Baby JubJub scalar-field element as a decimal string.
pub fn bjj_to_dec(s: &BjjFr) -> String {
    num_bigint::BigUint::from_bytes_be(&s.into_bigint().to_bytes_be()).to_string()
}

/// Domain separators and key-derivation prefixes.
///
/// These are reproduced verbatim from Nightfall (`nf4_new`) and must match
/// `../noir/src/domains.nr`.
pub mod domains {
    use super::{Fr254, PrimeField};

    /// `DOMAIN_KEM` (`nf4 lib/src/plonk_prover/circuits/mod.rs:7-8`).
    pub fn domain_kem() -> Fr254 {
        super::fr_from_dec(
            "21033365405711675223813179268586447041622169155539365736392974498519442361181",
        )
    }
    /// `DOMAIN_DEM` (`nf4 lib/src/plonk_prover/circuits/mod.rs:9-10`).
    pub fn domain_dem() -> Fr254 {
        super::fr_from_dec(
            "1241463701002173366467794894814691939898321302682516549591039420117995599097",
        )
    }
    /// `NULLIFIER_PREFIX` (`nf4 lib/src/derive_key.rs:42-44`).
    pub fn nullifier_prefix() -> Fr254 {
        super::fr_from_dec(
            "7805187439118198468809896822299973897593108379494079213870562208229492109015",
        )
    }
    /// `PRIVATE_KEY_PREFIX` (`nf4 lib/src/derive_key.rs:40-41`).
    pub fn private_key_prefix() -> Fr254 {
        super::fr_from_dec(
            "2708019456231621178814538244712057499818649907582893776052749473028258908910",
        )
    }
    /// Deposit nullifier domain: `Fr254::from_le_bytes_mod_order(b"DEPOSIT_NULLIFIER_V1")`
    /// (`nf4 lib/src/plonk_prover/circuits/verify/verify_nullifiers_gadgets.rs:16-18`).
    pub fn deposit_nullifier_domain() -> Fr254 {
        Fr254::from_le_bytes_mod_order(b"DEPOSIT_NULLIFIER_V1")
    }

    /// `DOMAIN_SHARED_SALT` — the salt for the recipient's note commitment is
    /// `Poseidon(ss.x, ss.y, DOMAIN_SHARED_SALT)` (not the raw `ss.y`).
    /// (`nf4 lib/src/plonk_prover/circuits/mod.rs:18-19`).
    pub fn domain_shared_salt() -> Fr254 {
        super::fr_from_dec(
            "4832298308599927878911686715232824310149976768223104556783163253807065458",
        )
    }

    /// Swap-link domain separator: `Fr254::from_le_bytes_mod_order(b"SWAP_V1")`
    /// (`nf4 lib/src/plonk_prover/circuits/unified_circuit.rs:287-288`).
    pub fn swap_domain() -> Fr254 {
        Fr254::from_le_bytes_mod_order(b"SWAP_V1")
    }

    /// Public-input framing word: `Fr254::from_le_bytes_mod_order(b"public_inputsversion2")`
    /// (`nf4 lib/src/plonk_prover/circuits/unified_circuit.rs:450-453`,
    /// `nf_client_proof.rs:161-165`).
    pub fn public_inputs_framing() -> Fr254 {
        Fr254::from_le_bytes_mod_order(b"public_inputsversion2")
    }
}

/// Poseidon sponge (state width 4, rate 3), matching jf's `SpongePoseidonHashGadget`
/// used to build `swap_link` (`nf4 unified_circuit.rs:289-305`). Absorbs `inputs`
/// in chunks of 3 into state positions `[1, 2, 3]`, permuting (the width-4 Poseidon
/// permutation) after each chunk, then squeezes `state[0]`.
pub mod sponge {
    use super::Fr254;
    use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
    use jf_primitives::poseidon::sponge::{PoseidonSponge, CRHF_RATE};
    use jf_primitives::poseidon::PoseidonPerm;

    /// Absorb `inputs` and squeeze a single field element.
    pub fn hash(inputs: &[Fr254]) -> Fr254 {
        let perm = PoseidonPerm::<Fr254>::perm().expect("poseidon width-4 permutation");
        let mut sponge = PoseidonSponge::<Fr254, CRHF_RATE>::new(&perm);
        sponge.absorb(&inputs.to_vec());
        sponge.squeeze_native_field_elements(1)[0]
    }
}

/// Binary Poseidon Merkle membership (`nf4 lib/src/merkle_trees/trees.rs:407-428`,
/// `verify_nullifiers_gadgets.rs:83`). Parent node = `Poseidon(left, right)`; each
/// path element carries a sibling and a direction (`sibling_on_left`).
pub mod merkle {
    use super::{poseidon, Fr254};

    /// One sibling step of a membership path.
    #[derive(Clone, Copy, Debug)]
    pub struct PathElement {
        /// The sibling node value at this level.
        pub sibling: Fr254,
        /// `true` if the sibling is the left child (`HashWithThisNodeOnLeft`).
        pub sibling_on_left: bool,
    }

    /// Hash `node` with its sibling, respecting direction.
    pub fn parent(node: Fr254, step: &PathElement) -> Fr254 {
        if step.sibling_on_left {
            poseidon::hash(&[step.sibling, node])
        } else {
            poseidon::hash(&[node, step.sibling])
        }
    }

    /// Recompute the Merkle root from a leaf and its sibling path.
    pub fn compute_root(leaf: Fr254, path: &[PathElement]) -> Fr254 {
        let mut node = leaf;
        for step in path {
            node = parent(node, step);
        }
        node
    }
}

/// Poseidon (= circomlib/iden3 = the noir-lang `poseidon` library).
pub mod poseidon {
    use super::{FieldHasher, Fr254, Poseidon};

    /// Fixed-length Poseidon hash over `inputs`.
    pub fn hash(inputs: &[Fr254]) -> Fr254 {
        Poseidon::<Fr254>::new()
            .hash(inputs)
            .expect("poseidon hash failed")
    }
}

/// Deposit-mode hashing (`nf4 deposit_witness.rs` + jf `full_shifted_sha256_hash`).
///
/// A deposit slot's public data is `SHA256(be32(token) || be32(slot) || be32(value)
/// || be32(secret_hash)) >> 4` — the 256-bit big-endian digest with its low 4 bits
/// dropped (the jf gadget splits off `digest & 0xF` and keeps the top 252 bits).
/// Anchored against nf4's real in-circuit gadget by `examples/anchor_sha256.rs`.
pub mod deposit {
    use super::{Fr254, PrimeField};
    use ark_ff::BigInteger;
    use sha2::{Digest, Sha256};

    /// Serialize a field element as its 32-byte big-endian representation, the
    /// layout jf's `preprocess` feeds into SHA256 (8 big-endian 32-bit words).
    fn be32(x: &Fr254) -> [u8; 32] {
        let mut out = [0u8; 32];
        let be = x.into_bigint().to_bytes_be(); // 32 bytes for BN254 Fr
        out.copy_from_slice(&be);
        out
    }

    /// `SHA256(be32(inputs[0]) || … ) >> 4`, the deposit public-data value.
    pub fn sha256_shift(inputs: &[Fr254]) -> Fr254 {
        let mut hasher = Sha256::new();
        for x in inputs {
            hasher.update(be32(x));
        }
        let digest = hasher.finalize(); // 32 bytes, big-endian
        let full = num_bigint::BigUint::from_bytes_be(&digest);
        let shifted = full >> 4u32;
        Fr254::from(shifted)
    }
}

/// Baby JubJub group operations via `nf_curves`.
pub mod bjj {
    use super::{AffineRepr, BjjFr, CurveGroup, Point};

    /// The fixed generator `G`.
    pub fn generator() -> Point {
        Point::generator()
    }

    /// `scalar · base`.
    pub fn scalar_mul(scalar: BjjFr, base: Point) -> Point {
        (base * scalar).into_affine()
    }

    /// `scalar · G`.
    pub fn mul_by_generator(scalar: BjjFr) -> Point {
        scalar_mul(scalar, generator())
    }

    /// M3: assert that `p` is on the curve AND in the prime-order subgroup before
    /// it is used as a Diffie-Hellman scalar-mul base. The neutral element passes
    /// both checks, so the withdraw/deposit (neutral recipient) case is allowed.
    pub fn assert_in_subgroup(p: &Point) {
        assert!(p.is_on_curve(), "bjj: DH base not on curve");
        assert!(
            p.is_in_correct_subgroup_assuming_on_curve(),
            "bjj: DH base not in prime-order subgroup"
        );
    }
}

/// Key derivation from the root key (`nf4 lib/src/derive_key.rs`).
pub mod keys {
    use super::{domains, poseidon, BigInteger, BjjFr, Fr254, PrimeField};

    /// `nullifier_key = Poseidon(root_key, NULLIFIER_PREFIX)`.
    pub fn nullifier_key(root_key: Fr254) -> Fr254 {
        poseidon::hash(&[root_key, domains::nullifier_prefix()])
    }

    /// `zkp_private_key = from_be_bytes_mod_order(Poseidon(root_key, PRIVATE_KEY_PREFIX))`
    /// reduced into the Baby JubJub scalar field.
    pub fn zkp_private_key(root_key: Fr254) -> BjjFr {
        zkp_private_key_witness(root_key).0
    }

    /// Derive the zkp private key together with the in-circuit witness data
    /// nf4 enforces (`unified_circuit.rs:124-150`):
    /// returns `(scalar, hash, lambda)` such that
    /// `hash == scalar + lambda * l` with `scalar < l` and `lambda < 8`,
    /// where `hash = Poseidon(root_key, PRIVATE_KEY_PREFIX)` and `l` is the
    /// Baby JubJub subgroup order.
    pub fn zkp_private_key_witness(root_key: Fr254) -> (BjjFr, Fr254, Fr254) {
        use num_bigint::BigUint;
        let h = poseidon::hash(&[root_key, domains::private_key_prefix()]);
        let scalar = BjjFr::from_be_bytes_mod_order(&h.into_bigint().to_bytes_be());

        let h_big = BigUint::from_bytes_be(&h.into_bigint().to_bytes_be());
        let scalar_big = BigUint::from_bytes_be(&scalar.into_bigint().to_bytes_be());
        let l_big = BigUint::from_bytes_be(&<BjjFr as PrimeField>::MODULUS.to_bytes_be());
        let lambda_big = (&h_big - &scalar_big) / &l_big;
        let lambda = Fr254::from_le_bytes_mod_order(&lambda_big.to_bytes_le());

        // M2: no-wrap guard (mirrors the in-circuit constraint). The reduction
        // `scalar + lambda * l == h` must hold over the integers without wrapping
        // the BN254 modulus `p`. Because `8 * l > p`, an alternate (wrapped)
        // witness with `lambda == 7` is only excluded if `scalar < p - 7 * l`.
        // The canonical witness computed here never wraps, so these assertions are
        // documentation/parity anchors that fail closed on any bad witness.
        let p_big = BigUint::from_bytes_be(&<Fr254 as PrimeField>::MODULUS.to_bytes_be());
        assert!(&lambda_big < &BigUint::from(8u8), "M2: reduction quotient >= 8");
        assert!(
            &scalar_big + &lambda_big * &l_big < p_big,
            "M2: BN254->BJJ reduction wraps the field modulus"
        );

        (scalar, h, lambda)
    }
}

/// KEM-DEM.
pub mod kemdem {
    use super::{domains, poseidon, Fr254, Point};

    /// KEM: `enc_key = Poseidon(ss.x, ss.y, DOMAIN_KEM)`.
    pub fn derive_enc_key(ss: &Point) -> Fr254 {
        poseidon::hash(&[ss.x, ss.y, domains::domain_kem()])
    }

    /// DEM keystream field for `counter`.
    pub fn dem_keystream(enc_key: Fr254, counter: Fr254) -> Fr254 {
        poseidon::hash(&[enc_key, domains::domain_dem(), counter])
    }

    /// `cipher = keystream(counter) + plain`.
    pub fn dem_encrypt_field(enc_key: Fr254, counter: Fr254, plain: Fr254) -> Fr254 {
        dem_keystream(enc_key, counter) + plain
    }

    /// Encrypt the full plaintext vector with counters `0..N`.
    pub fn dem_encrypt(enc_key: Fr254, plains: &[Fr254]) -> Vec<Fr254> {
        plains
            .iter()
            .enumerate()
            .map(|(i, &p)| dem_encrypt_field(enc_key, Fr254::from(i as u64), p))
            .collect()
    }
}

/// Note commitment + nullifier (`nf4 lib/src/shared_entities.rs`,
/// `verify_commitments_gadgets.rs`, `verify_nullifiers_gadgets.rs`).
pub mod note {
    use super::{domains, keys, poseidon, Fr254, Point};

    /// Arity-6 note commitment: `Poseidon(token_id, slot_id, value, pk.x, pk.y, salt)`.
    pub fn commitment(
        token_id: Fr254,
        slot_id: Fr254,
        value: Fr254,
        pk: &Point,
        salt: Fr254,
    ) -> Fr254 {
        poseidon::hash(&[token_id, slot_id, value, pk.x, pk.y, salt])
    }

    /// `nullifier = Poseidon(nullifier_key, commitment)`.
    pub fn nullifier(root_key: Fr254, commitment: Fr254) -> Fr254 {
        poseidon::hash(&[keys::nullifier_key(root_key), commitment])
    }

    /// Deposit nullifier key: `Poseidon(sp0, sp1, sp2, DEPOSIT_NULLIFIER_V1)` (arity-4).
    pub fn deposit_nullifier_key(secret_preimage: &[Fr254; 3]) -> Fr254 {
        poseidon::hash(&[
            secret_preimage[0],
            secret_preimage[1],
            secret_preimage[2],
            domains::deposit_nullifier_domain(),
        ])
    }
}

pub mod statement;
pub mod predvm;
pub mod notev2;
pub mod statement_v2;

/// Private witness for the (single-note) client transaction statement.
///
/// All keys are *derived* from `root_key`, matching nf4. The note value is
/// encrypted (KEM-DEM) and committed; the same note is nullified (self-spend) so
/// the nullifier formula is anchored.
#[derive(Clone, Debug)]
pub struct ClientInputs {
    /// Root key; `zkp_private_key` and `nullifier_key` are derived from it.
    pub root_key: Fr254,
    /// Ephemeral KEM scalar (Baby JubJub subgroup scalar).
    pub ephemeral: BjjFr,
    /// Note token id (`nf_token_id`).
    pub nf_token_id: Fr254,
    /// Note slot id (ERC-3525 `nf_slot_id`).
    pub nf_slot_id: Fr254,
    /// Note value.
    pub value: Fr254,
    /// Deposit secret preimage (anchors the arity-4 deposit nullifier key).
    pub secret_preimage: [Fr254; 3],
}

impl ClientInputs {
    /// Build the canonical reference inputs from small integers.
    pub fn from_u64(
        root_key: u64,
        ephemeral: u64,
        nf_token_id: u64,
        nf_slot_id: u64,
        value: u64,
        secret_preimage: [u64; 3],
    ) -> Self {
        Self {
            root_key: Fr254::from(root_key),
            ephemeral: BjjFr::from(ephemeral),
            nf_token_id: Fr254::from(nf_token_id),
            nf_slot_id: Fr254::from(nf_slot_id),
            value: Fr254::from(value),
            secret_preimage: secret_preimage.map(Fr254::from),
        }
    }
}

/// Full intermediate + output trace of the client statement.
#[derive(Clone, Debug)]
pub struct ClientTrace {
    /// Derived zkp private key (Baby JubJub scalar).
    pub zkp_priv: BjjFr,
    /// Unreduced derivation hash `Poseidon(root_key, PRIVATE_KEY_PREFIX)`.
    pub zkp_priv_hash: Fr254,
    /// Reduction quotient `lambda = (hash - zkp_priv) / l` (in-circuit witness).
    pub zkp_priv_lambda: Fr254,
    /// Owner public key `pk = zkp_priv · G`.
    pub pk: Point,
    /// Shared secret `ss = ephemeral · pk`.
    pub ss: Point,
    /// Ephemeral public key `epk = ephemeral · G`.
    pub epk: Point,
    /// KEM encryption key.
    pub enc_key: Fr254,
    /// DEM ciphertext fields for `[nf_token_id, nf_slot_id, value]`.
    pub ciphers: [Fr254; 3],
    /// `epk.x` parity flag (`is_lt(-epk.x, epk.x)`).
    pub x_parity: Fr254,
    /// `compressed_secrets = [c0, c1, c2, epk.y, x_parity]`.
    pub compressed_secrets: [Fr254; 5],
    /// Commitment salt (= shared-secret y, per nf4's first commitment).
    pub salt: Fr254,
    /// Note commitment.
    pub commitment: Fr254,
    /// Nullifier key `Poseidon(root_key, NULLIFIER_PREFIX)`.
    pub null_key: Fr254,
    /// Nullifier `Poseidon(null_key, commitment)`.
    pub nullifier: Fr254,
    /// Deposit nullifier key `Poseidon(sp0, sp1, sp2, DEPOSIT_NULLIFIER_V1)`.
    pub deposit_null_key: Fr254,
}

/// `is_lt(-x, x)` over the canonical integer representation, as in nf4's
/// `verify_encryption_gadgets.rs:37-44`.
fn x_parity_flag(x: Fr254) -> Fr254 {
    let neg_x = -x;
    if neg_x.into_bigint() < x.into_bigint() {
        Fr254::from(1u64)
    } else {
        Fr254::from(0u64)
    }
}

/// Compute the full client crypto path with the real Nightfish primitives.
pub fn compute_client(inputs: &ClientInputs) -> ClientTrace {
    // Keys are derived from the root key (nf4 parity).
    let (zkp_priv, zkp_priv_hash, zkp_priv_lambda) = keys::zkp_private_key_witness(inputs.root_key);
    assert!(!zkp_priv.is_zero(), "derived zkp_private_key is zero");
    assert!(!inputs.ephemeral.is_zero(), "ephemeral scalar is zero");

    let pk = bjj::mul_by_generator(zkp_priv);
    let ss = bjj::scalar_mul(inputs.ephemeral, pk);
    let epk = bjj::mul_by_generator(inputs.ephemeral);

    // KEM-DEM over the real plaintext [nf_token_id, nf_slot_id, value].
    let enc_key = kemdem::derive_enc_key(&ss);
    let plains = [inputs.nf_token_id, inputs.nf_slot_id, inputs.value];
    let cipher_vec = kemdem::dem_encrypt(enc_key, &plains);
    let ciphers = [cipher_vec[0], cipher_vec[1], cipher_vec[2]];
    let x_parity = x_parity_flag(epk.x);
    let compressed_secrets = [ciphers[0], ciphers[1], ciphers[2], epk.y, x_parity];

    // First (transfer) commitment uses shared_secret.y as its salt.
    let salt = ss.y;
    let commitment = note::commitment(
        inputs.nf_token_id,
        inputs.nf_slot_id,
        inputs.value,
        &pk,
        salt,
    );
    let null_key = keys::nullifier_key(inputs.root_key);
    let nullifier = note::nullifier(inputs.root_key, commitment);
    let deposit_null_key = note::deposit_nullifier_key(&inputs.secret_preimage);

    ClientTrace {
        zkp_priv,
        zkp_priv_hash,
        zkp_priv_lambda,
        pk,
        ss,
        epk,
        enc_key,
        ciphers,
        x_parity,
        compressed_secrets,
        salt,
        commitment,
        null_key,
        nullifier,
        deposit_null_key,
    }
}

/// Canonical reference inputs.
pub fn reference_inputs() -> ClientInputs {
    ClientInputs::from_u64(31337, 555555, 7, 3, 1000, [11, 22, 33])
}

/// Serializable parity-vector record (decimal-string fields) for
/// `../vectors/client_ref.json`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VectorJson {
    pub inputs: VectorInputs,
    pub outputs: VectorOutputs,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VectorInputs {
    pub root_key: String,
    pub ephemeral: String,
    pub nf_token_id: String,
    pub nf_slot_id: String,
    pub value: String,
    pub secret_preimage: [String; 3],
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VectorOutputs {
    pub zkp_priv: String,
    pub zkp_priv_hash: String,
    pub zkp_priv_lambda: String,
    pub pk_x: String,
    pub pk_y: String,
    pub ss_x: String,
    pub ss_y: String,
    pub epk_x: String,
    pub epk_y: String,
    pub enc_key: String,
    pub ciphers: [String; 3],
    pub x_parity: String,
    pub compressed_secrets: [String; 5],
    pub salt: String,
    pub commitment: String,
    pub null_key: String,
    pub nullifier: String,
    pub deposit_null_key: String,
}

/// Build the JSON record from the canonical reference inputs.
pub fn reference_vector_json() -> VectorJson {
    let inputs = reference_inputs();
    let t = compute_client(&inputs);
    VectorJson {
        inputs: VectorInputs {
            root_key: fr_to_dec(&inputs.root_key),
            ephemeral: bjj_to_dec(&inputs.ephemeral),
            nf_token_id: fr_to_dec(&inputs.nf_token_id),
            nf_slot_id: fr_to_dec(&inputs.nf_slot_id),
            value: fr_to_dec(&inputs.value),
            secret_preimage: inputs.secret_preimage.map(|f| fr_to_dec(&f)),
        },
        outputs: VectorOutputs {
            zkp_priv: bjj_to_dec(&t.zkp_priv),
            zkp_priv_hash: fr_to_dec(&t.zkp_priv_hash),
            zkp_priv_lambda: fr_to_dec(&t.zkp_priv_lambda),
            pk_x: fr_to_dec(&t.pk.x),
            pk_y: fr_to_dec(&t.pk.y),
            ss_x: fr_to_dec(&t.ss.x),
            ss_y: fr_to_dec(&t.ss.y),
            epk_x: fr_to_dec(&t.epk.x),
            epk_y: fr_to_dec(&t.epk.y),
            enc_key: fr_to_dec(&t.enc_key),
            ciphers: t.ciphers.map(|f| fr_to_dec(&f)),
            x_parity: fr_to_dec(&t.x_parity),
            compressed_secrets: t.compressed_secrets.map(|f| fr_to_dec(&f)),
            salt: fr_to_dec(&t.salt),
            commitment: fr_to_dec(&t.commitment),
            null_key: fr_to_dec(&t.null_key),
            nullifier: fr_to_dec(&t.nullifier),
            deposit_null_key: fr_to_dec(&t.deposit_null_key),
        },
    }
}
