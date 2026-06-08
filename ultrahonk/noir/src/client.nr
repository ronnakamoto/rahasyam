//! The high-level Nightfall client-transaction statement (single-note).
//!
//! Composes the library primitives into the leaf statement a client proves,
//! reproducing nf4's **real** client crypto path with all keys derived from the
//! root key:
//!
//! ```text
//!   zkp_priv   = reduce(Poseidon(root_key, PRIVATE_KEY_PREFIX))     (witness + check)
//!   pk         = zkp_priv · G                                       (Baby JubJub, a = 1)
//!   ss         = ephemeral · pk
//!   epk        = ephemeral · G
//!   enc_key    = Poseidon(ss.x, ss.y, DOMAIN_KEM)                   (KEM)
//!   cipher_i   = Poseidon(enc_key, DOMAIN_DEM, i) + plain_i         (DEM, i = 0..2)
//!   plain      = [nf_token_id, nf_slot_id, value]
//!   secrets    = [cipher0, cipher1, cipher2, epk.y, x_parity]
//!   salt       = ss.y
//!   commitment = Poseidon(nf_token_id, nf_slot_id, value, pk.x, pk.y, salt)
//!   nullifier  = Poseidon(Poseidon(root_key, NULLIFIER_PREFIX), commitment)
//! ```
//!
//! `deposit_null_key = Poseidon(sp0, sp1, sp2, DEPOSIT_NULLIFIER_DOMAIN)` anchors the
//! arity-4 deposit nullifier-key gadget.

use crate::bjj;
use crate::kemdem;
use crate::keys;
use crate::note;

/// Private witness for the client transaction statement.
pub struct ClientInputs {
    /// Root key; the zkp private key and nullifier key are derived from it.
    pub root_key: Field,
    /// Witnessed reduced zkp private key (Baby JubJub subgroup scalar).
    pub zkp_priv: Field,
    /// Witnessed reduction quotient (`hash = zkp_priv + lambda * l`, `lambda < 8`).
    pub zkp_priv_lambda: Field,
    /// Ephemeral key for the KEM (Baby JubJub subgroup scalar).
    pub ephemeral: Field,
    /// Note token id (`nf_token_id`).
    pub nf_token_id: Field,
    /// Note slot id (ERC-3525 `nf_slot_id`).
    pub nf_slot_id: Field,
    /// Note value (constrained to 96 bits).
    pub value: Field,
    /// Deposit secret preimage (anchors the deposit nullifier key).
    pub secret_preimage: [Field; 3],
}

/// Public outputs of the client transaction statement.
pub struct ClientOutputs {
    pub commitment: Field,
    pub nullifier: Field,
    /// `[cipher0, cipher1, cipher2, epk.y, x_parity]`.
    pub compressed_secrets: [Field; 5],
    pub deposit_null_key: Field,
}

/// The `epk.x` parity flag: `is_lt(-x, x)` over the canonical integer
/// representation (`nf4 verify_encryption_gadgets.rs:37-44`).
fn x_parity(x: Field) -> Field {
    let neg_x = 0 - x;
    neg_x.lt(x) as Field
}

/// Run the client statement, enforcing all constraints and returning the public
/// outputs.
pub fn prove_client_tx(inputs: ClientInputs) -> ClientOutputs {
    // Derive + constrain the zkp private key from the root key (fail-closed).
    let zkp_priv =
        keys::derive_zkp_private_key(inputs.root_key, inputs.zkp_priv, inputs.zkp_priv_lambda);

    // Range / subgroup hardening before any proving work.
    bjj::assert_valid_scalar(inputs.ephemeral);
    assert(inputs.ephemeral != 0, "client: ephemeral scalar is zero");
    inputs.value.assert_max_bit_size::<96>();

    let pk = bjj::mul_by_generator(zkp_priv);
    let ss = bjj::scalar_mul(inputs.ephemeral, pk);
    let epk = bjj::mul_by_generator(inputs.ephemeral);
    bjj::assert_on_curve(pk);
    bjj::assert_on_curve(ss);
    bjj::assert_on_curve(epk);

    // KEM-DEM over the real plaintext [nf_token_id, nf_slot_id, value].
    let enc_key = kemdem::derive_enc_key(ss);
    let plains = [inputs.nf_token_id, inputs.nf_slot_id, inputs.value];
    let ciphers = kemdem::dem_encrypt(enc_key, plains);
    let parity = x_parity(epk.x);
    let compressed_secrets = [ciphers[0], ciphers[1], ciphers[2], epk.y, parity];

    // First (transfer) commitment uses shared_secret.y as its salt.
    let salt = ss.y;
    let commitment =
        note::commitment(inputs.nf_token_id, inputs.nf_slot_id, inputs.value, pk, salt);
    let nullifier = note::nullifier(inputs.root_key, commitment);
    let deposit_null_key = note::deposit_nullifier_key(inputs.secret_preimage);

    ClientOutputs { commitment, nullifier, compressed_secrets, deposit_null_key }
}
