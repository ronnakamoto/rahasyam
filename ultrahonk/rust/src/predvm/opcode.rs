//! Opcode definitions and the committed script encoding.
//!
//! A predicate script is a fixed `[OpCode; MAX_OPS]` array. Short scripts are
//! right-padded with [`OpCode::Nop`], whose encoding is `(tag = 0, immediate = 0)`.
//! Every other non-`PUSH` opcode also has immediate `0`; [`OpCode::Push`] is the
//! only opcode that commits an immediate word today. The frozen commitment is:
//!
//! ```text
//! predicate_root(script) = SpongePoseidon(
//!   PREDVM_ROOT_V1,
//!   MAX_OPS,
//!   tag(script[0]), immediate(script[0]),
//!   ...,
//!   tag(script[MAX_OPS - 1]), immediate(script[MAX_OPS - 1])
//! )
//! ```
//!
//! The sponge is the same width-4/rate-3 Poseidon sponge exported by the crate
//! root. The domain word is `Fr254::from_le_bytes_mod_order(b"PREDVM_ROOT_V1")`.
//! This is intentionally simple to mirror in Noir and in an UltraHonk lookup
//! table: the circuit constrains one stable tag and one immediate lane per row.

use super::MAX_OPS;
use crate::sponge;
use ark_bn254::Fr as Fr254;
use ark_ff::{PrimeField, Zero};

/// Domain separator for predicate-script commitments.
pub fn predicate_root_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_ROOT_V1")
}

/// The bounded predicate-VM opcode menu.
///
/// Tags are stable protocol values. Do not reorder or reuse them: `tag()` is the
/// value note-format-v2 binds through [`predicate_root`], and future circuits will
/// use the same values in their opcode lookup table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpCode {
    /// Padding / explicit no-op. Encodes as `(0, 0)`.
    Nop,
    /// Push one BN254 scalar-field element onto the witness stack.
    Push(Fr254),
    /// Duplicate the stack top.
    Dup,
    /// Drop the stack top.
    Drop,
    /// Swap the top two stack elements.
    Swap,
    /// Pop `a, b`; push `1` iff `a == b`, else `0`.
    Equal,
    /// Pop `a, b`; abort unless `a == b`.
    EqualVerify,
    /// Pop `a, b`; push `1` iff canonical integer `a < b`, else `0`.
    LessThan,
    /// Pop `a, b`; push `1` iff canonical integer `a > b`, else `0`.
    GreaterThan,
    /// Pop `a, b`; push boolean `a && b` under non-zero truthiness.
    BoolAnd,
    /// Pop `a, b`; push boolean `a || b` under non-zero truthiness.
    BoolOr,
    /// Pop `a, b`; push field addition `a + b`.
    Add,
    /// Pop `a, b`; push field subtraction `a - b`.
    Sub,
    /// Begin a masked branch, consuming the condition when the parent branch is active.
    If,
    /// Switch to the opposite side of the current masked branch.
    Else,
    /// End the current masked branch.
    EndIf,
    /// Baby-JubJub signature authorization hook. Implemented by `predvm-auth`.
    CheckSig,
    /// Baby-JubJub m-of-n authorization hook. Implemented by `predvm-auth`.
    CheckMultiSig,
    /// Poseidon hash / hash-lock hook. Implemented by `predvm-time-hash`.
    Hash,
    /// Absolute timelock against the rollup clock. Implemented by `predvm-time-hash`.
    CheckLockTimeVerify,
    /// Relative timelock against the rollup sequence. Implemented by `predvm-time-hash`.
    CheckSequenceVerify,
    /// Oracle / IoT data-signature hook from the proposal's `OP_CHECKDATASIG`.
    CheckDataSig,
    /// Covenant hook: assert output predicates / policy propagation.
    CheckOutputPredicate,
    /// Covenant hook: recipient introspection.
    CheckRecipient,
    /// Covenant hook: amount check.
    CheckAmount,
    /// Covenant hook: value introspection.
    InspectValue,
    /// Compliance hook: KYC membership / freshness.
    CheckKyc,
    /// Compliance hook: revocation non-membership.
    CheckNotRevoked,
    /// Compliance hook: sanctions non-membership.
    CheckNotSanctioned,
    /// Compliance hook: KYC tier predicate.
    CheckKycTier,
    /// Compliance hook: jurisdiction predicate.
    CheckJurisdiction,
    /// Compliance hook: selective-disclosure audit.
    Audit,
    /// L1 state-proof hook.
    CheckL1State,
}

impl OpCode {
    /// Stable `u8` opcode tag used by the reference oracle and the Noir mirror.
    pub const fn tag_u8(&self) -> u8 {
        match self {
            Self::Nop => 0,
            Self::Push(_) => 1,
            Self::Dup => 2,
            Self::Drop => 3,
            Self::Swap => 4,
            Self::Equal => 5,
            Self::EqualVerify => 6,
            Self::LessThan => 7,
            Self::GreaterThan => 8,
            Self::BoolAnd => 9,
            Self::BoolOr => 10,
            Self::Add => 11,
            Self::Sub => 12,
            Self::If => 13,
            Self::Else => 14,
            Self::EndIf => 15,
            Self::CheckSig => 16,
            Self::CheckMultiSig => 17,
            Self::Hash => 18,
            Self::CheckLockTimeVerify => 19,
            Self::CheckSequenceVerify => 20,
            Self::CheckDataSig => 21,
            Self::CheckOutputPredicate => 22,
            Self::CheckRecipient => 23,
            Self::CheckAmount => 24,
            Self::InspectValue => 25,
            Self::CheckKyc => 26,
            Self::CheckNotRevoked => 27,
            Self::CheckNotSanctioned => 28,
            Self::CheckKycTier => 29,
            Self::CheckJurisdiction => 30,
            Self::Audit => 31,
            Self::CheckL1State => 32,
        }
    }

    /// Stable field tag for the opcode lookup table.
    pub fn tag(&self) -> Fr254 {
        Fr254::from(self.tag_u8() as u64)
    }

    /// Immediate lane committed next to the tag.
    ///
    /// Only [`OpCode::Push`] uses this lane in the foundation VM. Future opcode
    /// extensions must either keep their parameters on the stack/witness, or
    /// explicitly version the commitment encoding before assigning immediates.
    pub fn immediate(&self) -> Fr254 {
        match self {
            Self::Push(v) => *v,
            _ => Fr254::zero(),
        }
    }

    /// Two-field row encoded into [`predicate_root`]: `(tag, immediate)`.
    pub fn encoded_fields(&self) -> [Fr254; 2] {
        [self.tag(), self.immediate()]
    }
}

/// Compute the note-bound predicate commitment for a fixed-size opcode array.
pub fn predicate_root(script: &[OpCode; MAX_OPS]) -> Fr254 {
    let mut words = Vec::with_capacity(2 + (2 * MAX_OPS));
    words.push(predicate_root_domain());
    words.push(Fr254::from(MAX_OPS as u64));
    for op in script {
        let [tag, immediate] = op.encoded_fields();
        words.push(tag);
        words.push(immediate);
    }
    sponge::hash(&words)
}
