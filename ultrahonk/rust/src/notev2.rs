//! Gated `note_format_v2` reference oracle: decoupled programmable assets plus
//! per-note stealth ownership keys.
//!
//! This module is deliberately additive. It does **not** edit the live v1
//! statement path or the existing frozen vectors in [`crate::statement`]. Adopting
//! v2 changes the committed preimage and therefore **breaks the frozen 27-word
//! statement vectors**; rollout must be gated behind an explicit `note_format_v2`
//! switch and a new parity-vector set.
//!
//! ## Commitment schema
//!
//! v1 commits directly to standard-shaped identifiers:
//!
//! ```text
//! Poseidon6(nf_token_id, nf_slot_id, value, pk.x, pk.y, salt)
//! ```
//!
//! v2 collapses all standard-specific identity fields (`nf_slot_id`, ERC class,
//! ERC-specific token/slot interpretation) behind one opaque, content-addressed
//! asset handle:
//!
//! ```text
//! asset_id   = Poseidon(asset_class_tag, token_contract, slot_id, predicate_root)
//! commitment = Poseidon6(asset_id, value, pk_onetime.x, pk_onetime.y, salt, mode_tag)
//! ```
//!
//! The hot commitment path stays arity-6 while `predicate_root` becomes part of
//! the asset identity. A plain ownership note is the special case whose predicate
//! root is the real predicate-VM commitment of the canonical `[PUSH(0), CHECKSIG]`
//! script (see [`checksig_predicate_root`]); the owner key is bound through the
//! note's committed `pk_onetime` plus a statement constraint, not through the
//! predicate root.
//!
//! ## Stealth address threat model
//!
//! Counterparties should not learn a stable owner key that links all payments to
//! a holder. A recipient publishes a dual-key meta-address `(A = a·G, B = b·G,
//! diversifier)`, where `a` is the spend key and `b` is the view key. For each
//! note, the sender samples an ephemeral scalar `r`, publishes `R = r·G`, computes
//! a Diffie-Hellman shared secret `r·B`, and sends to
//! `P = A + H(r·B, diversifier)·G`. The recipient detects the note with `b·R` and
//! spends using `p = a + H(b·R, diversifier)`. Every supplied DH base is checked to
//! be on-curve and in the prime-order subgroup before scalar multiplication.

use crate::predvm::{self, OpCode, MAX_OPS};
use crate::{bjj, keys, poseidon, Fr254, Point};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use nf_curves::ed_on_bn254::Fr as BjjFr;

/// Published recipient meta-address for v2 stealth notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifiedMetaAddress {
    /// Spend public key `A = a·G`; one-time addresses are `A + tweak·G`.
    pub spend_public: Point,
    /// View public key `B = b·G`; senders perform DH against this key.
    pub view_public: Point,
    /// Public domain/diversifier bound into the stealth tweak derivation.
    pub diversifier: Fr254,
}

fn tag(bytes: &'static [u8]) -> Fr254 {
    Fr254::from_le_bytes_mod_order(bytes)
}

fn stealth_tweak_tag() -> Fr254 {
    tag(b"NF4_NOTE_V2_STEALTH_TWEAK")
}

fn pairwise_pseudonym_tag() -> Fr254 {
    tag(b"NF4_NOTE_V2_PAIRWISE_PSEUDONYM")
}

fn view_key_prefix() -> Fr254 {
    tag(b"NF4_NOTE_V2_VIEW_KEY")
}

fn fr_to_bjj_scalar(f: Fr254, label: &str) -> BjjFr {
    let scalar = BjjFr::from_be_bytes_mod_order(&f.into_bigint().to_bytes_be());
    assert!(!scalar.is_zero(), "notev2: {label} reduced to zero scalar");
    scalar
}

fn bjj_scalar_to_fr(scalar: BjjFr) -> Fr254 {
    Fr254::from_le_bytes_mod_order(&scalar.into_bigint().to_bytes_le())
}

fn is_neutral(p: &Point) -> bool {
    p.x.is_zero() && p.y.is_one()
}

fn assert_spendable_public_key(p: &Point, label: &str) {
    bjj::assert_in_subgroup(p);
    assert!(!is_neutral(p), "notev2: {label} must not be neutral");
}

fn add_points(a: Point, b: Point) -> Point {
    (a.into_group() + b.into_group()).into_affine()
}

/// Opaque content-addressed asset identifier.
///
/// `slot_id` is interpreted by the asset class/predicate pair, not by the note
/// preimage. That is the decoupling win: the commitment no longer contains
/// `nf_slot_id` or any ERC-specific fields directly.
pub fn asset_id(
    asset_class_tag: Fr254,
    token_contract: Fr254,
    slot_id: Fr254,
    predicate_root: Fr254,
) -> Fr254 {
    poseidon::hash(&[asset_class_tag, token_contract, slot_id, predicate_root])
}

/// Arity-6 v2 note commitment.
///
/// `pk_onetime` must be a per-note stealth address, not the recipient's static
/// long-term key. `mode_tag` keeps transfer/deposit/withdraw/swap framing bound
/// without widening the arity beyond v1's six Poseidon inputs.
pub fn commitment_v2(
    asset_id: Fr254,
    value: Fr254,
    pk_onetime: &Point,
    salt: Fr254,
    mode_tag: Fr254,
) -> Fr254 {
    assert_spendable_public_key(pk_onetime, "one-time public key");
    poseidon::hash(&[asset_id, value, pk_onetime.x, pk_onetime.y, salt, mode_tag])
}

/// Predicate root for a plain `CHECKSIG(owner)` ownership note.
///
/// This is the real predicate-VM commitment of the canonical ownership script
/// `[PUSH(0), CHECKSIG]` (right-padded with `NOP`), computed by
/// [`crate::predvm::predicate_root`]. It is deliberately **owner-independent**: in
/// the predicate VM, `predicate_root` commits the *program* (opcode tags +
/// immediates), never runtime context. The signing key is supplied to `CHECKSIG`
/// through the statement-bound `EvalContext` signature hook, not the script.
///
/// ## Owner-binding contract (must be enforced by the v2 statement circuit)
///
/// Because the predicate root carries no key, the note's owner is bound in two
/// places that the v2 statement MUST tie together:
/// 1. `pk_onetime` is committed inside [`commitment_v2`]; and
/// 2. the statement MUST constrain the `CHECKSIG` hook's `public_key` to equal the
///    note's committed `pk_onetime`.
///
/// Without (2) any prover could substitute their own key into the hook and sign,
/// so this equality is a soundness-critical constraint, not an optimization. This
/// keeps the asset model decoupled — the asset's identity does not depend on who
/// currently holds it — while the spend authorization remains bound to the note.
pub fn checksig_predicate_root() -> Fr254 {
    let mut script = [OpCode::Nop; MAX_OPS];
    script[0] = OpCode::Push(Fr254::zero());
    script[1] = OpCode::CheckSig;
    predvm::predicate_root(&script)
}

/// Existing v1 spend key material, reused additively as the v2 stealth spend key.
pub fn derive_spend_private_key(root_key: Fr254) -> BjjFr {
    let spend = keys::zkp_private_key(root_key);
    assert!(!spend.is_zero(), "notev2: spend key is zero");
    spend
}

/// Additive v2 view key derived from the root key under a distinct prefix.
pub fn derive_view_private_key(root_key: Fr254) -> BjjFr {
    let h = poseidon::hash(&[root_key, view_key_prefix()]);
    fr_to_bjj_scalar(h, "view key")
}

/// Build the published dual-key meta-address from a root key and public diversifier.
pub fn meta_address_from_root_key(root_key: Fr254, diversifier: Fr254) -> DiversifiedMetaAddress {
    let spend_private = derive_spend_private_key(root_key);
    let view_private = derive_view_private_key(root_key);
    DiversifiedMetaAddress {
        spend_public: bjj::mul_by_generator(spend_private),
        view_public: bjj::mul_by_generator(view_private),
        diversifier,
    }
}

/// Sender-side stealth derivation.
///
/// Given the recipient's published meta-address and a fresh ephemeral scalar `r`,
/// returns the one-time note public key `P = A + H(r·B, diversifier)·G`.
pub fn derive_onetime_address(meta: &DiversifiedMetaAddress, ephemeral_scalar: BjjFr) -> Point {
    assert!(
        !ephemeral_scalar.is_zero(),
        "notev2: ephemeral scalar is zero"
    );
    assert_spendable_public_key(&meta.spend_public, "meta spend public key");
    assert_spendable_public_key(&meta.view_public, "meta view public key");

    let shared_secret = bjj::scalar_mul(ephemeral_scalar, meta.view_public);
    let tweak = stealth_tweak(&shared_secret, meta.diversifier);
    let tweak_public = bjj::mul_by_generator(tweak);
    let onetime = add_points(meta.spend_public, tweak_public);
    assert_spendable_public_key(&onetime, "derived one-time public key");
    onetime
}

/// Public ephemeral key `R = r·G` that accompanies a stealth note ciphertext.
pub fn ephemeral_public_key(ephemeral_scalar: BjjFr) -> Point {
    assert!(
        !ephemeral_scalar.is_zero(),
        "notev2: ephemeral scalar is zero"
    );
    bjj::mul_by_generator(ephemeral_scalar)
}

/// Recipient-side one-time private-key recovery.
///
/// The recipient recomputes `b·R`, derives the same tweak, and returns
/// `p = a + tweak`. Call [`can_spend`] against the advertised one-time public key
/// before treating the note as spendable.
pub fn recover_onetime_private(
    spend_private: BjjFr,
    view_private: BjjFr,
    ephemeral_public: &Point,
    diversifier: Fr254,
) -> BjjFr {
    assert!(
        !spend_private.is_zero(),
        "notev2: spend private key is zero"
    );
    assert!(!view_private.is_zero(), "notev2: view private key is zero");
    assert_spendable_public_key(ephemeral_public, "ephemeral public key");

    let shared_secret = bjj::scalar_mul(view_private, *ephemeral_public);
    let tweak = stealth_tweak(&shared_secret, diversifier);
    let onetime_private = spend_private + tweak;
    assert!(
        !onetime_private.is_zero(),
        "notev2: one-time private key is zero"
    );
    onetime_private
}

/// Verify that `onetime_private·G` equals the committed one-time public key.
pub fn can_spend(onetime_private: BjjFr, onetime_public: &Point) -> bool {
    if onetime_private.is_zero() {
        return false;
    }
    assert_spendable_public_key(onetime_public, "one-time public key");
    bjj::mul_by_generator(onetime_private) == *onetime_public
}

/// Derive the scalar tweak from a checked DH point and diversifier.
fn stealth_tweak(shared_secret: &Point, diversifier: Fr254) -> BjjFr {
    bjj::assert_in_subgroup(shared_secret);
    assert!(
        !is_neutral(shared_secret),
        "notev2: shared secret is neutral"
    );
    let h = poseidon::hash(&[
        stealth_tweak_tag(),
        shared_secret.x,
        shared_secret.y,
        diversifier,
    ]);
    fr_to_bjj_scalar(h, "stealth tweak")
}

/// Pairwise pseudonym for future KYC identity commitments.
///
/// This helper intentionally binds a holder secret to a counterparty and context
/// (for example an issuer, auditor, token family, or compliance realm). The same
/// holder can therefore disclose different pseudonyms in different contexts, so
/// two holdings cannot be linked merely because both carry a KYC predicate.
pub fn pairwise_pseudonym(
    view_private: BjjFr,
    counterparty_tag: Fr254,
    context_tag: Fr254,
) -> Fr254 {
    assert!(!view_private.is_zero(), "notev2: view private key is zero");
    poseidon::hash(&[
        pairwise_pseudonym_tag(),
        bjj_scalar_to_fr(view_private),
        counterparty_tag,
        context_tag,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fr_from_dec, fr_to_dec};

    fn recipient_root() -> Fr254 {
        Fr254::from(31_337u64)
    }

    fn reference_meta() -> DiversifiedMetaAddress {
        meta_address_from_root_key(recipient_root(), Fr254::from(99u64))
    }

    #[test]
    fn asset_id_and_commitment_v2_match_frozen_vectors() {
        let meta = reference_meta();
        let predicate = checksig_predicate_root();
        let asset = asset_id(
            Fr254::from(20u64),
            Fr254::from(0xabcdu64),
            Fr254::from(7u64),
            predicate,
        );
        let onetime = derive_onetime_address(&meta, BjjFr::from(55_555u64));
        let commitment = commitment_v2(
            asset,
            Fr254::from(1_000u64),
            &onetime,
            Fr254::from(424_242u64),
            Fr254::from(1u64),
        );

        assert_eq!(
            fr_to_dec(&predicate),
            "11689625243239651800916630189824673125461565769452488384025746456853898962882",
            "CHECKSIG predicate root drifted"
        );
        assert_eq!(
            fr_to_dec(&asset),
            "6472802526358006045551043019525853796095328226738052895525104462407757064581",
            "asset_id vector drifted"
        );
        assert_eq!(
            fr_to_dec(&commitment),
            "18719358169827126754329323430915302165569977545053615649473289911161013686837",
            "commitment_v2 vector drifted"
        );

        let asset_again = asset_id(
            Fr254::from(20u64),
            Fr254::from(0xabcdu64),
            Fr254::from(7u64),
            predicate,
        );
        let commitment_again = commitment_v2(
            asset_again,
            Fr254::from(1_000u64),
            &onetime,
            Fr254::from(424_242u64),
            Fr254::from(1u64),
        );
        assert_eq!(asset, asset_again, "asset_id must be deterministic");
        assert_eq!(
            commitment, commitment_again,
            "commitment_v2 must be deterministic"
        );

        // Reconciliation anchor: the ownership predicate root MUST equal the real
        // predicate-VM commitment of the canonical `[PUSH(0), CHECKSIG]` script, and
        // must be owner-independent (no key folded into the program commitment).
        let mut canonical = [crate::predvm::OpCode::Nop; crate::predvm::MAX_OPS];
        canonical[0] = crate::predvm::OpCode::Push(Fr254::zero());
        canonical[1] = crate::predvm::OpCode::CheckSig;
        assert_eq!(
            predicate,
            crate::predvm::predicate_root(&canonical),
            "ownership predicate root must equal the predvm script commitment"
        );
        let other_owner = meta_address_from_root_key(Fr254::from(424_242u64), Fr254::from(7u64));
        assert_ne!(
            meta.spend_public, other_owner.spend_public,
            "test setup: owners must differ"
        );
        assert_eq!(
            checksig_predicate_root(),
            predicate,
            "ownership predicate root must not depend on the owner key"
        );
    }

    #[test]
    fn stealth_round_trip_recovers_spendable_key() {
        let meta = reference_meta();
        let ephemeral = BjjFr::from(55_555u64);
        let onetime_public = derive_onetime_address(&meta, ephemeral);
        let epk = ephemeral_public_key(ephemeral);

        let spend_private = derive_spend_private_key(recipient_root());
        let view_private = derive_view_private_key(recipient_root());
        let onetime_private =
            recover_onetime_private(spend_private, view_private, &epk, meta.diversifier);
        assert!(
            can_spend(onetime_private, &onetime_public),
            "recipient must recover the spendable one-time private key"
        );

        let wrong_root = Fr254::from(31_338u64);
        let wrong_private = recover_onetime_private(
            derive_spend_private_key(wrong_root),
            derive_view_private_key(wrong_root),
            &epk,
            meta.diversifier,
        );
        assert_ne!(
            bjj::mul_by_generator(wrong_private),
            onetime_public,
            "wrong recipient must derive a different one-time key"
        );
        assert!(
            !can_spend(wrong_private, &onetime_public),
            "wrong recipient must not spend the note"
        );
    }

    #[test]
    fn same_recipient_two_notes_have_unlinkable_onetime_addresses() {
        let meta = reference_meta();
        let first = derive_onetime_address(&meta, BjjFr::from(1_001u64));
        let second = derive_onetime_address(&meta, BjjFr::from(1_002u64));
        assert_ne!(
            first, second,
            "fresh ephemeral scalars must produce different one-time addresses"
        );
    }

    #[test]
    fn pairwise_pseudonym_changes_by_counterparty_and_context() {
        let view_private = derive_view_private_key(recipient_root());
        let a = pairwise_pseudonym(view_private, Fr254::from(1u64), Fr254::from(7u64));
        let b = pairwise_pseudonym(view_private, Fr254::from(2u64), Fr254::from(7u64));
        let c = pairwise_pseudonym(view_private, Fr254::from(1u64), Fr254::from(8u64));
        assert_ne!(a, b, "counterparty tag must affect the pseudonym");
        assert_ne!(a, c, "context tag must affect the pseudonym");
        assert_eq!(
            fr_to_dec(&a),
            fr_to_dec(&pairwise_pseudonym(
                view_private,
                Fr254::from(1u64),
                Fr254::from(7u64)
            )),
            "pairwise pseudonym must be deterministic"
        );
        assert_ne!(a, fr_from_dec("0"), "pseudonym must be non-zero in vector");
    }
}
