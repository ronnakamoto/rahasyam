//! Hash-lock and timelock opcodes for the bounded predicate VM.
//!
//! Owned by the `predvm-time-hash` track. This module implements the hash-preimage
//! and relative/absolute timelock opcodes so the evaluator's `eval.rs` arms can
//! delegate. Keeping it in its own file lets the time/hash and auth tracks evolve
//! in parallel without colliding on a shared evaluator body.
//!
//! ## Opcodes
//!
//! - [`OpCode::Hash`]: pop a preimage opening from the stack/witness, compute the
//!   in-circuit Poseidon hash (`crate::poseidon` / `crate::sponge`), and push the
//!   digest. Pair with `EQUALVERIFY` for HTLC-style hash locks.
//! - [`OpCode::CheckLockTimeVerify`]: assert an absolute timelock against the
//!   rollup-provided [`EvalContext::clock`]; fail closed if the lock is not yet
//!   reached.
//! - [`OpCode::CheckSequenceVerify`]: assert a relative timelock against the
//!   rollup-provided [`EvalContext::sequence`]; fail closed if the age requirement
//!   is unmet.
//!
//! ## Soundness contract (must hold for every opcode added here)
//!
//! - **Fail closed.** A missing preimage, wrong digest, or unmet timelock must
//!   return an `EvalError`, never push a truthy result. No default-true path.
//! - **Canonical comparisons.** Timelock comparisons must use a canonical,
//!   range-checked ordering (`super::eval::canonical_lt`) so field wraparound can
//!   never make an unmet lock appear satisfied.
//! - **Domain separation.** Hash inputs must be domain-tagged (`crate::domains`) so
//!   a preimage opening cannot be cross-replayed into another hash context.
//! - **Bounded openings.** Preimage length is bounded; reject over-length openings
//!   rather than truncating.

use super::eval::{canonical_lt, EvalContext, EvalError, EvalWitness, Stack};
use super::opcode::OpCode;
use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};

/// Domain separator for hash-lock preimage hashing. Distinct from every other
/// transcript so a preimage opening can never be cross-replayed into another hash
/// context (e.g. a signature challenge or the predicate-root commitment).
fn hashlock_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_HASHLOCK_V1")
}

/// Maximum number of field elements in a single hash-lock preimage opening.
///
/// Openings are bounded so the circuit has a fixed worst-case absorb width and an
/// over-length opening is rejected outright rather than silently truncated (which
/// would let two different preimages collide onto the same committed digest).
pub(crate) const MAX_PREIMAGE_LEN: usize = 8;

/// Whether a time/hash opcode is still reserved (no constraints yet).
///
/// All three time/hash opcodes are implemented below, so none remain trapped. The
/// evaluator still calls this for the inactive-branch fail-closed gate; returning
/// `false` lets an implemented opcode be masked (no-op) under an inactive selector,
/// exactly like the structural opcodes.
pub(crate) fn is_reserved(_opcode: OpCode) -> bool {
    false
}

/// Decode a stack/witness field element as a bounded index.
///
/// Fails closed (returns `None`) for any value whose canonical integer does not fit
/// in a `usize`, so an attacker cannot smuggle a huge field element past a bounds
/// check by relying on a wrapping conversion.
fn fr_to_index(v: Fr254) -> Option<usize> {
    let bytes = v.into_bigint().to_bytes_le();
    if bytes.iter().skip(8).any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let raw = u64::from_le_bytes(buf);
    usize::try_from(raw).ok()
}

/// `HASH <i>`: open private preimage `i` and push its domain-separated digest.
///
/// Stack: pops the opening index `i`; pushes `digest`. Pair with the existing
/// `EQUALVERIFY` for an HTLC-style hash lock (`HASH <i>; PUSH <expected>;
/// EQUALVERIFY`). Fails closed on a missing/out-of-range index or an over-length
/// opening; there is no truncation or default-digest path.
fn op_hash(opcode: OpCode, stack: &mut Stack, witness: &EvalWitness) -> Result<(), EvalError> {
    let index = fr_to_index(stack.pop(opcode)?).ok_or(EvalError::VerifyFailed(opcode))?;
    let opening = witness
        .hash_preimages
        .get(index)
        .ok_or(EvalError::VerifyFailed(opcode))?;
    if opening.len() > MAX_PREIMAGE_LEN {
        return Err(EvalError::VerifyFailed(opcode));
    }
    // Domain-tag and length-prefix the opening so distinct-length preimages live in
    // disjoint transcripts and cannot be made to collide.
    let mut transcript = Vec::with_capacity(2 + opening.len());
    transcript.push(hashlock_domain());
    transcript.push(Fr254::from(opening.len() as u64));
    transcript.extend_from_slice(opening);
    let digest = crate::sponge::hash(&transcript);
    stack.push(opcode, digest)
}

/// Assert `observed >= threshold` using a canonical integer comparison.
///
/// `threshold` is popped from the stack. The comparison uses the canonical field
/// representative (`canonical_lt`), so a near-modulus `threshold` is treated as the
/// large integer it is — field wraparound can never make an unmet lock look
/// satisfied. *Verify* semantics: an unmet lock aborts the predicate (fail closed),
/// it does not push a boolean.
fn op_timelock_verify(opcode: OpCode, stack: &mut Stack, observed: Fr254) -> Result<(), EvalError> {
    let threshold = stack.pop(opcode)?;
    // satisfied iff observed >= threshold iff NOT (observed < threshold).
    if canonical_lt(observed, threshold) {
        return Err(EvalError::VerifyFailed(opcode));
    }
    Ok(())
}

/// Execute one hash/timelock opcode against the active value stack.
///
/// `stack` is the live evaluation stack, `witness` carries private preimage
/// openings, and `ctx` carries the rollup clock/sequence public inputs. Every path
/// fails closed: a missing witness, out-of-range index, over-length opening, or
/// unmet timelock returns an [`EvalError`] and never yields a truthy result.
pub(crate) fn execute(
    opcode: OpCode,
    stack: &mut Stack,
    witness: &EvalWitness,
    ctx: &EvalContext,
) -> Result<(), EvalError> {
    match opcode {
        OpCode::Hash => op_hash(opcode, stack, witness),
        OpCode::CheckLockTimeVerify => op_timelock_verify(opcode, stack, ctx.clock),
        OpCode::CheckSequenceVerify => op_timelock_verify(opcode, stack, ctx.sequence),
        // The evaluator only routes the three opcodes above here; anything else is a
        // dispatch bug and must fail closed rather than silently succeed.
        _ => Err(EvalError::Unimplemented(opcode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fr_to_dec;
    use crate::predvm::{evaluate, predicate_root, MAX_OPS};

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

    /// Recompute the committed digest exactly as `op_hash` does, for test scripts.
    fn digest_of(opening: &[Fr254]) -> Fr254 {
        let mut transcript = Vec::with_capacity(2 + opening.len());
        transcript.push(hashlock_domain());
        transcript.push(Fr254::from(opening.len() as u64));
        transcript.extend_from_slice(opening);
        crate::sponge::hash(&transcript)
    }

    #[test]
    fn hashlock_digest_matches_frozen_vector() {
        // Anchor the hash-lock transcript so the Noir gadget can be checked against
        // a fixed value and any accidental change to the domain/length framing is
        // caught.
        let opening = [f(111), f(222)];
        assert_eq!(
            fr_to_dec(&digest_of(&opening)),
            "1886598378541012845387901669226598508324626464749358652581333867415718362894",
        );
    }

    #[test]
    fn hashlock_round_trip_opens_and_verifies() {
        let opening = vec![f(111), f(222)];
        let expected = digest_of(&opening);
        let script = padded(&[
            OpCode::Push(f(0)),
            OpCode::Hash,
            OpCode::Push(expected),
            OpCode::EqualVerify,
            OpCode::Push(f(1)),
        ]);
        let witness = EvalWitness {
            hash_preimages: vec![opening],
            ..Default::default()
        };
        let got = evaluate(&script, &witness, &EvalContext::default())
            .expect("a correct hash-lock opening must verify");
        assert!(got, "hash-lock predicate must evaluate true");
        assert_eq!(
            fr_to_dec(&predicate_root(&script)),
            "8298953389529242353589847485923006494079357767572391157567312193189077279318",
        );
    }

    #[test]
    fn hashlock_wrong_preimage_fails_closed() {
        let expected = digest_of(&[f(111), f(222)]);
        let script = padded(&[
            OpCode::Push(f(0)),
            OpCode::Hash,
            OpCode::Push(expected),
            OpCode::EqualVerify,
            OpCode::Push(f(1)),
        ]);
        let witness = EvalWitness {
            hash_preimages: vec![vec![f(111), f(999)]],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &witness, &EvalContext::default()),
            Err(EvalError::VerifyFailed(OpCode::EqualVerify)),
            "a wrong preimage must fail closed at EQUALVERIFY",
        );
    }

    #[test]
    fn hashlock_overlength_opening_fails_closed() {
        let script = padded(&[OpCode::Push(f(0)), OpCode::Hash, OpCode::Push(f(1))]);
        let witness = EvalWitness {
            hash_preimages: vec![vec![f(1); MAX_PREIMAGE_LEN + 1]],
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &witness, &EvalContext::default()),
            Err(EvalError::VerifyFailed(OpCode::Hash)),
            "an over-length opening must be rejected, not truncated",
        );
    }

    #[test]
    fn hashlock_missing_opening_fails_closed() {
        let script = padded(&[OpCode::Push(f(0)), OpCode::Hash, OpCode::Push(f(1))]);
        let witness = EvalWitness::default();
        assert_eq!(
            evaluate(&script, &witness, &EvalContext::default()),
            Err(EvalError::VerifyFailed(OpCode::Hash)),
            "an out-of-range opening index must fail closed",
        );
    }

    #[test]
    fn cltv_satisfied_when_clock_at_or_past_threshold() {
        let script = padded(&[
            OpCode::Push(f(50)),
            OpCode::CheckLockTimeVerify,
            OpCode::Push(f(1)),
        ]);
        let ctx = EvalContext {
            clock: f(100),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Ok(true),
            "CLTV must pass once the clock has reached the threshold",
        );
    }

    #[test]
    fn cltv_not_reached_fails_closed() {
        let script = padded(&[
            OpCode::Push(f(50)),
            OpCode::CheckLockTimeVerify,
            OpCode::Push(f(1)),
        ]);
        let ctx = EvalContext {
            clock: f(40),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckLockTimeVerify)),
            "CLTV must abort while the absolute timelock is unmet",
        );
    }

    #[test]
    fn csv_satisfied_when_sequence_at_or_past_threshold() {
        let script = padded(&[
            OpCode::Push(f(5)),
            OpCode::CheckSequenceVerify,
            OpCode::Push(f(1)),
        ]);
        let ctx = EvalContext {
            sequence: f(10),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Ok(true),
            "CSV must pass once the relative age has reached the threshold",
        );
    }

    #[test]
    fn csv_unmet_fails_closed() {
        let script = padded(&[
            OpCode::Push(f(5)),
            OpCode::CheckSequenceVerify,
            OpCode::Push(f(1)),
        ]);
        let ctx = EvalContext {
            sequence: f(3),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckSequenceVerify)),
            "CSV must abort while the relative timelock is unmet",
        );
    }

    #[test]
    fn timelock_comparison_is_not_fooled_by_field_wraparound() {
        // threshold = p - 1 (the largest canonical representative). A naive modular
        // or signed comparison might treat this as "-1" and accept any clock; the
        // canonical comparison must treat it as a huge integer and reject clock = 5.
        let huge = Fr254::from(0u64) - Fr254::from(1u64);
        let script = padded(&[
            OpCode::Push(huge),
            OpCode::CheckLockTimeVerify,
            OpCode::Push(f(1)),
        ]);
        let ctx = EvalContext {
            clock: f(5),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&script, &EvalWitness::default(), &ctx),
            Err(EvalError::VerifyFailed(OpCode::CheckLockTimeVerify)),
            "a near-modulus threshold must not wrap into a trivially-satisfied lock",
        );
    }

    #[test]
    fn implemented_opcodes_are_no_longer_reserved() {
        for op in [
            OpCode::Hash,
            OpCode::CheckLockTimeVerify,
            OpCode::CheckSequenceVerify,
        ] {
            assert!(
                !is_reserved(op),
                "{op:?} must no longer be trapped as reserved"
            );
        }
    }
}
