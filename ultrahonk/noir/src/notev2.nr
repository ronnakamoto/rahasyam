//! Gated `note_format_v2` mirror for `ultrahonk/rust/src/notev2.rs`.
//!
//! This file mirrors the Rust reference-oracle formulas for the decoupled v2
//! asset id / commitment schema, plus a tractable stealth-address sketch using
//! witnessed BN254→Baby-JubJub reductions. It is validated by the Rust reference
//! module and frozen decimal vectors there. This environment cannot nargo-compile
//! the Noir mirror, so treat the Rust oracle as authoritative until Noir CI lands.
//!
//! Adopting this v2 preimage is a gated note-format change: it is not an in-place
//! edit of `note.nr`/`statement.nr`, and it intentionally breaks the existing
//! frozen 27-word statement vectors.

use crate::bjj;
use crate::bjj::Point;
use crate::hash;
use crate::script;

/// `Fr::from_le_bytes_mod_order(b"NF4_NOTE_V2_STEALTH_TWEAK")`.
global STEALTH_TWEAK_TAG: Field =
    472383067077396137136006994294001454012322491600640123618894;
/// `Fr::from_le_bytes_mod_order(b"NF4_NOTE_V2_PAIRWISE_PSEUDONYM")`.
global PAIRWISE_PSEUDONYM_TAG: Field =
    533842150923522013640671068655551210180305707132013739448747167610848846;
/// Same no-wrap guard as `keys.nr`: `FIELD_MODULUS - 7 * SUBGROUP_ORDER`.
global NO_WRAP_BOUND: Field =
    2736030358979909402780800718157159386010666595306063529296694559936676884330;

/// Published dual-key v2 meta-address.
pub struct DiversifiedMetaAddress {
    pub spend_public: Point,
    pub view_public: Point,
    pub diversifier: Field,
}

fn assert_non_neutral(p: Point) {
    assert(!bjj::is_neutral(p), "notev2: point must not be neutral");
}

fn assert_spendable_public_key(p: Point) {
    bjj::assert_in_subgroup(p);
    assert_non_neutral(p);
}

fn points_equal(a: Point, b: Point) -> bool {
    (a.x == b.x) & (a.y == b.y)
}

/// Opaque content-addressed asset identifier.
///
/// Standard-specific fields (`slot_id`, ERC class/type semantics, and future
/// schema axes) are represented only by this hash. They are not v2 note-preimage
/// fields. `predicate_root` is bound into the asset id, not appended as a seventh
/// hot-path commitment input.
pub fn asset_id(
    asset_class_tag: Field,
    token_contract: Field,
    slot_id: Field,
    predicate_root: Field,
) -> Field {
    hash::hash4(asset_class_tag, token_contract, slot_id, predicate_root)
}

/// Arity-6 v2 note commitment.
pub fn commitment_v2(
    asset_id: Field,
    value: Field,
    pk_onetime: Point,
    salt: Field,
    mode_tag: Field,
) -> Field {
    assert_spendable_public_key(pk_onetime);
    hash::hash6(asset_id, value, pk_onetime.x, pk_onetime.y, salt, mode_tag)
}

/// Predicate root for a plain `CHECKSIG(owner)` ownership note.
///
/// This is the real predicate-VM commitment of the canonical ownership script
/// `[PUSH(0), CHECKSIG]` (right-padded with `NOP`), computed by
/// [`crate::script::predicate_root`]. It is deliberately **owner-independent**: in
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
/// so this equality is a soundness-critical constraint, not an optimization.
pub fn checksig_predicate_root() -> Field {
    let mut program: [script::OpCode; script::MAX_OPS] = [script::OpCode { tag: script::TAG_NOP, immediate: 0 }; script::MAX_OPS];
    program[0] = script::push(0);
    program[1] = script::OpCode { tag: script::TAG_CHECKSIG, immediate: 0 };
    script::predicate_root(program)
}

/// Witness and constrain a BN254 hash reduction into the Baby JubJub subgroup.
///
/// Mirrors `keys.nr`: `hash == scalar + lambda * l`, `scalar < l`, `lambda < 8`,
/// and the `lambda == 7` no-wrap guard. This is needed because the Rust stealth
/// tweak uses `BjjFr::from_be_bytes_mod_order(hash)`.
fn constrain_bjj_reduction(hash_value: Field, scalar: Field, lambda: Field) -> Field {
    assert(scalar + lambda * bjj::SUBGROUP_ORDER == hash_value, "notev2: scalar reduction mismatch");
    bjj::assert_valid_scalar(scalar);
    assert(lambda.lt(8), "notev2: reduction quotient out of range");
    assert(scalar != 0, "notev2: reduced scalar is zero");
    let guarded = if lambda == 7 { scalar } else { 0 };
    assert(guarded.lt(NO_WRAP_BOUND), "notev2: scalar reduction wraps the field modulus");
    scalar
}

/// Sender-side stealth derivation with witnessed tweak reduction.
///
/// `ephemeral_scalar` is the sender's fresh `r`; `tweak`/`lambda` witness the
/// reduction of `Poseidon(STEALTH_TWEAK_TAG, (r·B).x, (r·B).y, diversifier)`.
pub fn derive_onetime_address(
    meta: DiversifiedMetaAddress,
    ephemeral_scalar: Field,
    tweak: Field,
    lambda: Field,
) -> Point {
    bjj::assert_valid_scalar(ephemeral_scalar);
    assert(ephemeral_scalar != 0, "notev2: ephemeral scalar is zero");
    assert_spendable_public_key(meta.spend_public);
    assert_spendable_public_key(meta.view_public);

    let shared_secret = bjj::scalar_mul(ephemeral_scalar, meta.view_public);
    assert_non_neutral(shared_secret);
    let h = hash::hash4(STEALTH_TWEAK_TAG, shared_secret.x, shared_secret.y, meta.diversifier);
    let t = constrain_bjj_reduction(h, tweak, lambda);
    let onetime = bjj::add(meta.spend_public, bjj::mul_by_generator(t));
    assert_spendable_public_key(onetime);
    onetime
}

/// Recipient-side recovery of `p = a + H(b·R, diversifier) mod l`.
pub fn recover_onetime_private(
    spend_private: Field,
    view_private: Field,
    ephemeral_public: Point,
    diversifier: Field,
    tweak: Field,
    lambda: Field,
) -> Field {
    bjj::assert_valid_scalar(spend_private);
    bjj::assert_valid_scalar(view_private);
    assert(spend_private != 0, "notev2: spend private key is zero");
    assert(view_private != 0, "notev2: view private key is zero");
    assert_spendable_public_key(ephemeral_public);

    let shared_secret = bjj::scalar_mul(view_private, ephemeral_public);
    assert_non_neutral(shared_secret);
    let h = hash::hash4(STEALTH_TWEAK_TAG, shared_secret.x, shared_secret.y, diversifier);
    let t = constrain_bjj_reduction(h, tweak, lambda);

    let raw = spend_private + t;
    let reduced = if raw.lt(bjj::SUBGROUP_ORDER) { raw } else { raw - bjj::SUBGROUP_ORDER };
    bjj::assert_valid_scalar(reduced);
    assert(reduced != 0, "notev2: one-time private key is zero");
    reduced
}

/// Fail-closed spendability check: `onetime_private · G == onetime_public`.
pub fn can_spend(onetime_private: Field, onetime_public: Point) -> bool {
    bjj::assert_valid_scalar(onetime_private);
    assert_spendable_public_key(onetime_public);
    points_equal(bjj::mul_by_generator(onetime_private), onetime_public)
}

/// Pairwise pseudonym for future KYC identity commitments.
///
/// Binding a holder secret to `(counterparty_tag, context_tag)` prevents two
/// holdings from being linked merely because both carry a KYC predicate.
pub fn pairwise_pseudonym(
    view_private: Field,
    counterparty_tag: Field,
    context_tag: Field,
) -> Field {
    bjj::assert_valid_scalar(view_private);
    assert(view_private != 0, "notev2: view private key is zero");
    hash::hash4(PAIRWISE_PSEUDONYM_TAG, view_private, counterparty_tag, context_tag)
}
