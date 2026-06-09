//! Authentication opcodes for the bounded predicate VM.
//!
//! Owned by the `predvm-auth` track. This module implements the spend-authorization
//! opcodes so the evaluator's `eval.rs` arms can delegate without growing. Keeping
//! the implementation in its own file lets the auth and time/hash tracks evolve in
//! parallel without colliding on a shared evaluator body.
//!
//! ## Opcodes
//!
//! - [`OpCode::CheckSig`]: verify a single Baby JubJub EdDSA/Schnorr signature over
//!   the statement-bound message in the matching [`SignatureHook`].
//! - [`OpCode::CheckMultiSig`]: verify an `m`-of-`n` threshold over a
//!   [`MultisigHook`], failing closed on under-supply or duplicate signers.
//! - [`OpCode::CheckDataSig`]: verify a signature over an explicit data message
//!   (covenant/oracle attestations) rather than the spend transcript.
//!
//! ## Soundness contract (must hold for every opcode added here)
//!
//! - **Fail closed.** Any missing witness, malformed point, off-curve key,
//!   wrong-subgroup point, or failed verification must return an `EvalError`, never
//!   push a truthy result. There is no default-true path.
//! - **Domain separation.** The in-circuit message transcript must be domain-tagged
//!   and bound to the full statement (predicate_root + public inputs), so a
//!   signature for one context can never be replayed into another.
//! - **Subgroup checks.** Validate every public key and signature point is on-curve
//!   and in the prime-order subgroup before use (reuse `crate::bjj` helpers).
//! - **Canonical scalars.** Reject non-canonical / out-of-range signature scalars
//!   (strict `s < L`) to kill malleability.

use super::eval::{bool_field, EvalContext, EvalError, EvalWitness, Stack};
use super::opcode::OpCode;
use crate::Point;
use ark_bn254::Fr as Fr254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use nf_curves::ed_on_bn254::Fr as BjjFr;
use num_bigint::BigUint;

/// Fiat–Shamir domain for `CHECKSIG` (spend-authorization signatures).
fn checksig_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKSIG_V1")
}

/// Fiat–Shamir domain for `CHECKDATASIG` (oracle / data attestations). Distinct from
/// [`checksig_domain`] so a spend-authorizing signature can never be replayed as a
/// data attestation, or vice versa.
fn datasig_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKDATASIG_V1")
}

/// Fiat–Shamir domain for the component signatures inside `CHECKMULTISIG`.
fn multisig_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKMULTISIG_V1")
}

/// Whether an auth opcode is still reserved (no constraints yet).
///
/// All three auth opcodes are implemented below, so none remain trapped. The
/// evaluator still calls this for the inactive-branch fail-closed gate; returning
/// `false` lets an implemented opcode be masked (no-op) under an inactive selector,
/// exactly like the structural opcodes.
pub(crate) fn is_reserved(_opcode: OpCode) -> bool {
    false
}

/// Decode a stack/witness field element as a bounded index, failing closed for any
/// value that does not fit in a `usize` (no wrapping conversion).
fn fr_to_index(v: Fr254) -> Option<usize> {
    let bytes = v.into_bigint().to_bytes_le();
    if bytes.iter().skip(8).any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    usize::try_from(u64::from_le_bytes(buf)).ok()
}

/// On-curve AND prime-order-subgroup membership, excluding the neutral element.
///
/// Baby JubJub has cofactor 8, so an on-curve point may still lie in a small-order
/// coset; the subgroup check rejects those. The neutral element `O = (0, 1)` passes
/// both checks (it is in every subgroup) but is rejected here as defense-in-depth:
/// as a public key `A = O` collapses verification to `z·G == R`, which anyone who
/// knows `dlog(R)` can satisfy with the trivial secret `0`. A spend/oracle key must
/// be a real, non-identity group element, so we fail closed on `O` for both the
/// public key and the nonce point `R`.
fn valid_point(p: &Point) -> bool {
    !is_neutral(p) && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}

/// The twisted-Edwards neutral element on Baby JubJub is `(0, 1)`.
fn is_neutral(p: &Point) -> bool {
    p.x.is_zero() && p.y.is_one()
}

/// The Baby JubJub scalar-field order `L` as a big integer.
fn subgroup_order() -> BigUint {
    BigUint::from_bytes_be(&<BjjFr as PrimeField>::MODULUS.to_bytes_be())
}

/// Decode a signature response scalar, rejecting any non-canonical encoding
/// (`z >= L`). Strict canonicality kills signature malleability: a single valid
/// signature must have exactly one accepted encoding.
fn canonical_scalar(z_fr: Fr254) -> Option<BjjFr> {
    let z_big = BigUint::from_bytes_be(&z_fr.into_bigint().to_bytes_be());
    if z_big >= subgroup_order() {
        return None;
    }
    Some(BjjFr::from_le_bytes_mod_order(
        &z_fr.into_bigint().to_bytes_le(),
    ))
}

/// Reduce a BN254 Poseidon output into the Baby JubJub scalar field for use as a
/// Fiat–Shamir challenge. Mirrors the reduction discipline in `crate::keys`.
fn reduce_to_bjj(c_fr: Fr254) -> BjjFr {
    BjjFr::from_be_bytes_mod_order(&c_fr.into_bigint().to_bytes_be())
}

/// Strong Fiat–Shamir challenge: binds the domain, the public key, the nonce point
/// `R`, AND the full message transcript. Hashing only `R` (weak FS) is forgeable
/// (Frozen-Heart class); every public value that pins the statement is absorbed.
///
/// The variable-length `message` is length-prefixed before it is absorbed. The
/// Poseidon sponge (rate 3) applies no padding, so absorbing `M` and `M‖0…0`
/// (zero-extension within the final rate block) yields the *same* state and hence
/// the same challenge — i.e. without framing a signature over `M` would also verify
/// over a distinct `M′ = M‖0`. Prefixing `len(message)` puts distinct-length
/// messages in disjoint transcripts and closes that collision, mirroring the
/// length-framing discipline already used by `OP_HASH`.
fn challenge(domain: Fr254, pk: &Point, r_point: &Point, message: &[Fr254]) -> BjjFr {
    let mut transcript = Vec::with_capacity(6 + message.len());
    transcript.push(domain);
    transcript.push(pk.x);
    transcript.push(pk.y);
    transcript.push(r_point.x);
    transcript.push(r_point.y);
    transcript.push(Fr254::from(message.len() as u64));
    transcript.extend_from_slice(message);
    reduce_to_bjj(crate::sponge::hash(&transcript))
}

/// Verify one Schnorr / EdDSA signature over Baby JubJub.
///
/// Scheme: secret `s`, public `A = s·G`; signature `(R, z)` with
/// `c = H(domain, A, R, message)` and the verification equation `z·G == R + c·A`.
///
/// Returns:
/// - `Ok(true)` / `Ok(false)` for a well-formed signature that does / does not
///   satisfy the verification equation (a legitimate boolean outcome), and
/// - `Err(VerifyFailed)` for malformed material — an off-curve / off-subgroup point
///   or a non-canonical response scalar. Malformed input fails closed; it is never
///   treated as a verifying signature.
fn verify_schnorr(
    opcode: OpCode,
    domain: Fr254,
    pk: &Point,
    message: &[Fr254],
    r_x: Fr254,
    r_y: Fr254,
    z_fr: Fr254,
) -> Result<bool, EvalError> {
    if !valid_point(pk) {
        return Err(EvalError::VerifyFailed(opcode));
    }
    let r_point = Point::new_unchecked(r_x, r_y);
    if !valid_point(&r_point) {
        return Err(EvalError::VerifyFailed(opcode));
    }
    let z = canonical_scalar(z_fr).ok_or(EvalError::VerifyFailed(opcode))?;

    let c = challenge(domain, pk, &r_point, message);
    let lhs = crate::bjj::mul_by_generator(z);
    let rhs = (r_point.into_group() + crate::bjj::scalar_mul(c, *pk)).into_affine();
    Ok(lhs == rhs)
}

/// `CHECKSIG` / `CHECKDATASIG`: pop an index `i`, verify
/// `(witness.signatures[i])` against `(ctx.signature_hooks[i])` under `domain`, and
/// push the boolean result. Out-of-range index, missing material, or a malformed
/// signature encoding fail closed.
fn op_checksig(
    opcode: OpCode,
    stack: &mut Stack,
    witness: &EvalWitness,
    ctx: &EvalContext,
    domain: Fr254,
) -> Result<(), EvalError> {
    let index = fr_to_index(stack.pop(opcode)?).ok_or(EvalError::VerifyFailed(opcode))?;
    let hook = ctx
        .signature_hooks
        .get(index)
        .ok_or(EvalError::VerifyFailed(opcode))?;
    let sig = witness
        .signatures
        .get(index)
        .ok_or(EvalError::VerifyFailed(opcode))?;
    if sig.fields.len() != 3 {
        return Err(EvalError::VerifyFailed(opcode));
    }
    let ok = verify_schnorr(
        opcode,
        domain,
        &hook.public_key,
        &hook.message,
        sig.fields[0],
        sig.fields[1],
        sig.fields[2],
    )?;
    stack.push(opcode, bool_field(ok))
}

/// `CHECKMULTISIG`: pop an index `i`, verify an `m`-of-`n` threshold over
/// `ctx.multisig_hooks[i]` using the component signatures in `witness.multisig[i]`,
/// and push the boolean result.
///
/// Witness layout (`fields`): `[m, (signer_idx, R.x, R.y, z) × m]`. The signer
/// indices MUST be strictly increasing and in range — this both forbids signer
/// reuse (the classic m-of-n duplicate-key forgery) and fixes a canonical ordering.
/// `m` must equal the hook threshold, which must be in `1..=n`. Structural
/// violations fail closed; a correctly-encoded set in which some signature does not
/// verify pushes `false`.
fn op_checkmultisig(
    opcode: OpCode,
    stack: &mut Stack,
    witness: &EvalWitness,
    ctx: &EvalContext,
) -> Result<(), EvalError> {
    let index = fr_to_index(stack.pop(opcode)?).ok_or(EvalError::VerifyFailed(opcode))?;
    let hook = ctx
        .multisig_hooks
        .get(index)
        .ok_or(EvalError::VerifyFailed(opcode))?;
    let material = witness
        .multisig
        .get(index)
        .ok_or(EvalError::VerifyFailed(opcode))?;

    let n = hook.public_keys.len();
    if hook.threshold == 0 || hook.threshold > n {
        return Err(EvalError::VerifyFailed(opcode));
    }
    if material.fields.is_empty() {
        return Err(EvalError::VerifyFailed(opcode));
    }
    let m = fr_to_index(material.fields[0]).ok_or(EvalError::VerifyFailed(opcode))?;
    if m != hook.threshold {
        return Err(EvalError::VerifyFailed(opcode));
    }
    if material.fields.len() != 1 + 4 * m {
        return Err(EvalError::VerifyFailed(opcode));
    }

    let mut all_ok = true;
    let mut prev_signer: Option<usize> = None;
    for group in 0..m {
        let base = 1 + 4 * group;
        let signer = fr_to_index(material.fields[base]).ok_or(EvalError::VerifyFailed(opcode))?;
        if signer >= n {
            return Err(EvalError::VerifyFailed(opcode));
        }
        if let Some(prev) = prev_signer {
            if signer <= prev {
                // Non-increasing index => duplicate or unordered signer. Fail closed.
                return Err(EvalError::VerifyFailed(opcode));
            }
        }
        prev_signer = Some(signer);

        let ok = verify_schnorr(
            opcode,
            multisig_domain(),
            &hook.public_keys[signer],
            &hook.message,
            material.fields[base + 1],
            material.fields[base + 2],
            material.fields[base + 3],
        )?;
        all_ok &= ok;
    }
    stack.push(opcode, bool_field(all_ok))
}

/// Execute one authentication opcode against the active value stack.
///
/// `stack` is the live evaluation stack, `witness` carries the private signature
/// material, and `ctx` carries the public verification hooks. Every path fails
/// closed on malformed material and never yields a truthy result without a verified
/// signature.
pub(crate) fn execute(
    opcode: OpCode,
    stack: &mut Stack,
    witness: &EvalWitness,
    ctx: &EvalContext,
) -> Result<(), EvalError> {
    match opcode {
        OpCode::CheckSig => op_checksig(opcode, stack, witness, ctx, checksig_domain()),
        OpCode::CheckDataSig => op_checksig(opcode, stack, witness, ctx, datasig_domain()),
        OpCode::CheckMultiSig => op_checkmultisig(opcode, stack, witness, ctx),
        // The evaluator only routes the three opcodes above here; anything else is a
        // dispatch bug and must fail closed rather than silently succeed.
        _ => Err(EvalError::Unimplemented(opcode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predvm::{
        evaluate, predicate_root, MultisigHook, SignatureHook, SignatureWitness, MAX_OPS,
    };
    use crate::{bjj, fr_to_dec};

    fn padded(prefix: &[OpCode]) -> [OpCode; MAX_OPS] {
        assert!(prefix.len() <= MAX_OPS, "test script exceeds MAX_OPS");
        let mut script = [OpCode::Nop; MAX_OPS];
        for (i, op) in prefix.iter().copied().enumerate() {
            script[i] = op;
        }
        script
    }

    fn f(v: u64) -> Fr254 {
        Fr254::from(v)
    }

    /// Honest signer: produces `(R.x, R.y, z)` for secret `s`, nonce `r`, message.
    fn sign(domain: Fr254, s: BjjFr, r: BjjFr, message: &[Fr254]) -> (Fr254, Fr254, Fr254) {
        let pk = bjj::mul_by_generator(s);
        let r_point = bjj::mul_by_generator(r);
        let c = challenge(domain, &pk, &r_point, message);
        let z = r + c * s;
        let z_fr = Fr254::from_le_bytes_mod_order(&z.into_bigint().to_bytes_le());
        (r_point.x, r_point.y, z_fr)
    }

    fn checksig_witness(rx: Fr254, ry: Fr254, z: Fr254) -> EvalWitness {
        EvalWitness {
            signatures: vec![SignatureWitness {
                fields: vec![rx, ry, z],
            }],
            ..Default::default()
        }
    }

    fn checksig_ctx(pk: Point, message: Vec<Fr254>) -> EvalContext {
        EvalContext {
            signature_hooks: vec![SignatureHook {
                public_key: pk,
                message,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn public_key_matches_frozen_vector() {
        // Anchor the keypair so the Noir EdDSA gadget can be checked against a fixed
        // public key for a known secret scalar.
        let pk = bjj::mul_by_generator(BjjFr::from(12345u64));
        assert_eq!(
            fr_to_dec(&pk.x),
            "14106934532433864949312079284331880791040638692107914922935991663049242140784",
        );
        assert_eq!(
            fr_to_dec(&pk.y),
            "10138170802840274768567272717966364309093303187476239561704593742321249054672",
        );
    }

    #[test]
    fn checksig_verifies_valid_signature() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let message = vec![f(1), f(2), f(3)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        let ctx = checksig_ctx(pk, message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(true),
            "an honest signature must verify",
        );
        assert_eq!(
            fr_to_dec(&predicate_root(&script)),
            "11689625243239651800916630189824673125461565769452488384025746456853898962882",
        );
    }

    #[test]
    fn checksig_rejects_forged_response_scalar() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let message = vec![f(1), f(2), f(3)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        // Tamper z by +1: still canonical, but the equation no longer holds.
        let witness = checksig_witness(rx, ry, z + f(1));
        let ctx = checksig_ctx(pk, message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(false),
            "a forged response scalar must not verify",
        );
    }

    #[test]
    fn checksig_rejects_tampered_message() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let signed = vec![f(1), f(2), f(3)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &signed);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        // Verify against a different message: the challenge changes, equation fails.
        let ctx = checksig_ctx(pk, vec![f(1), f(2), f(4)]);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(false),
            "a signature must not verify against a tampered message",
        );
    }

    #[test]
    fn checksig_rejects_trailing_zero_message_extension() {
        // Soundness regression: the Poseidon sponge (rate 3) applies no padding, so
        // hash(M) == hash(M‖0) when the extra zero falls in the final rate block.
        // Without length-framing the FS challenge would be identical for M and M‖0,
        // letting a signature over M verify over the distinct message M‖0. Confirm
        // the length prefix in `challenge` closes this.
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let message = vec![f(1), f(2)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        // Same signature, message zero-extended within the final rate block.
        let mut extended = message.clone();
        extended.push(f(0));
        let ctx = checksig_ctx(pk, extended);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(false),
            "a signature over M must not verify over the zero-extended message M‖0",
        );
    }

    #[test]
    fn checksig_rejects_cross_domain_replay() {
        // A CHECKDATASIG-domain signature must not satisfy CHECKSIG: the domain is
        // bound into the Fiat–Shamir challenge.
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let message = vec![f(7), f(8)];
        let (rx, ry, z) = sign(datasig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        let ctx = checksig_ctx(pk, message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(false),
            "a data-signature must not be replayable as a spend signature",
        );
    }

    #[test]
    fn checksig_fails_closed_on_offcurve_key() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let message = vec![f(1)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        // (1, 1) is not on the Baby JubJub curve.
        let ctx = checksig_ctx(Point::new_unchecked(f(1), f(1)), message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckSig)),
            "an off-curve public key must fail closed",
        );
    }

    #[test]
    fn checksig_fails_closed_on_noncanonical_scalar() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let pk = bjj::mul_by_generator(s);
        let message = vec![f(1)];
        let (rx, ry, _z) = sign(checksig_domain(), s, r, &message);

        // z encoded as exactly the subgroup order L (>= L) is non-canonical.
        let l_fr = Fr254::from_le_bytes_mod_order(&<BjjFr as PrimeField>::MODULUS.to_bytes_le());
        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, l_fr);
        let ctx = checksig_ctx(pk, message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckSig)),
            "a non-canonical response scalar must fail closed",
        );
    }

    #[test]
    fn checksig_fails_closed_on_neutral_key() {
        let s = BjjFr::from(12345u64);
        let r = BjjFr::from(67890u64);
        let message = vec![f(1)];
        let (rx, ry, z) = sign(checksig_domain(), s, r, &message);

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let witness = checksig_witness(rx, ry, z);
        // The neutral element O = (0, 1) is on-curve and in-subgroup but must be
        // rejected as a public key: A = O would make verification trivially forgeable.
        let ctx = checksig_ctx(Point::new_unchecked(Fr254::zero(), Fr254::one()), message);

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckSig)),
            "the neutral element must not be accepted as a public key",
        );
    }

    #[test]
    fn checksig_fails_closed_on_missing_witness() {
        let pk = bjj::mul_by_generator(BjjFr::from(12345u64));
        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckSig]);
        let ctx = checksig_ctx(pk, vec![f(1)]);

        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckSig)),
            "a missing signature witness must fail closed",
        );
    }

    fn multisig_group(
        domain: Fr254,
        signer: usize,
        s: BjjFr,
        r: BjjFr,
        message: &[Fr254],
    ) -> Vec<Fr254> {
        let (rx, ry, z) = sign(domain, s, r, message);
        vec![f(signer as u64), rx, ry, z]
    }

    #[test]
    fn checkmultisig_two_of_three_verifies() {
        let secrets = [BjjFr::from(11u64), BjjFr::from(22u64), BjjFr::from(33u64)];
        let keys: Vec<Point> = secrets.iter().map(|s| bjj::mul_by_generator(*s)).collect();
        let message = vec![f(9), f(9)];

        let mut fields = vec![f(2)];
        fields.extend(multisig_group(
            multisig_domain(),
            0,
            secrets[0],
            BjjFr::from(100u64),
            &message,
        ));
        fields.extend(multisig_group(
            multisig_domain(),
            2,
            secrets[2],
            BjjFr::from(200u64),
            &message,
        ));

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckMultiSig]);
        let witness = EvalWitness {
            multisig: vec![super::super::eval::MultisigWitness { fields }],
            ..Default::default()
        };
        let ctx = EvalContext {
            multisig_hooks: vec![MultisigHook {
                threshold: 2,
                public_keys: keys,
                message,
            }],
            ..Default::default()
        };

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(true),
            "a valid 2-of-3 multisig must verify",
        );
    }

    #[test]
    fn checkmultisig_rejects_duplicate_signer() {
        let secrets = [BjjFr::from(11u64), BjjFr::from(22u64), BjjFr::from(33u64)];
        let keys: Vec<Point> = secrets.iter().map(|s| bjj::mul_by_generator(*s)).collect();
        let message = vec![f(9), f(9)];

        // Two signatures from signer 0 (non-increasing index) — duplicate-key forgery.
        let mut fields = vec![f(2)];
        fields.extend(multisig_group(
            multisig_domain(),
            0,
            secrets[0],
            BjjFr::from(100u64),
            &message,
        ));
        fields.extend(multisig_group(
            multisig_domain(),
            0,
            secrets[0],
            BjjFr::from(200u64),
            &message,
        ));

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckMultiSig]);
        let witness = EvalWitness {
            multisig: vec![super::super::eval::MultisigWitness { fields }],
            ..Default::default()
        };
        let ctx = EvalContext {
            multisig_hooks: vec![MultisigHook {
                threshold: 2,
                public_keys: keys,
                message,
            }],
            ..Default::default()
        };

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckMultiSig)),
            "duplicate / non-increasing signer indices must fail closed",
        );
    }

    #[test]
    fn checkmultisig_pushes_false_on_one_bad_signature() {
        let secrets = [BjjFr::from(11u64), BjjFr::from(22u64), BjjFr::from(33u64)];
        let keys: Vec<Point> = secrets.iter().map(|s| bjj::mul_by_generator(*s)).collect();
        let message = vec![f(9), f(9)];

        let mut fields = vec![f(2)];
        fields.extend(multisig_group(
            multisig_domain(),
            0,
            secrets[0],
            BjjFr::from(100u64),
            &message,
        ));
        // Signer 2's component signed by the wrong key (secret 11 instead of 33).
        fields.extend(multisig_group(
            multisig_domain(),
            2,
            secrets[0],
            BjjFr::from(200u64),
            &message,
        ));

        let script = padded(&[OpCode::Push(f(0)), OpCode::CheckMultiSig]);
        let witness = EvalWitness {
            multisig: vec![super::super::eval::MultisigWitness { fields }],
            ..Default::default()
        };
        let ctx = EvalContext {
            multisig_hooks: vec![MultisigHook {
                threshold: 2,
                public_keys: keys,
                message,
            }],
            ..Default::default()
        };

        assert_eq!(
            evaluate(&script, &witness, &ctx),
            Ok(false),
            "a well-formed set with one invalid signature must evaluate false",
        );
    }

    #[test]
    fn implemented_opcodes_are_no_longer_reserved() {
        for op in [
            OpCode::CheckSig,
            OpCode::CheckMultiSig,
            OpCode::CheckDataSig,
        ] {
            assert!(
                !is_reserved(op),
                "{op:?} must no longer be trapped as reserved"
            );
        }
    }
}
