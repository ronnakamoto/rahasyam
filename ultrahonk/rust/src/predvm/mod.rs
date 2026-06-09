//! # Bounded predicate VM (Option B mini-zkVM)
//!
//! This module is the Rust reference oracle for programmable UTXO-token spend
//! predicates. It intentionally implements the **bounded unrolled** architecture
//! from the design note instead of a general zkVM: a script is exactly
//! [`MAX_OPS`] opcode rows, padded with [`OpCode::Nop`], and evaluation always
//! visits all rows with no program counter and no user loops.
//!
//! ## Commitment contract
//!
//! [`predicate_root`] is the value note-format-v2 should bind into an asset/note.
//! The committed script shape is fixed and crisp:
//!
//! ```text
//! predicate_root(script) = SpongePoseidon(
//!   Fr254::from_le_bytes_mod_order(b"PREDVM_ROOT_V1"),
//!   MAX_OPS,
//!   tag_0, immediate_0,
//!   ...,
//!   tag_{MAX_OPS-1}, immediate_{MAX_OPS-1}
//! )
//! ```
//!
//! `tag_i` is the stable field tag returned by [`OpCode::tag`]. `immediate_i` is
//! the pushed field element for `PUSH(x)` and `0` for every other opcode. This
//! gives the circuit one lookup tag and one immediate lane per row, while keeping
//! short scripts domain-separated from any future bound change by committing
//! `MAX_OPS` itself.
//!
//! ## Cost tradeoff
//!
//! [`MAX_OPS`] and [`STACK_DEPTH`] are deliberately modest. UltraHonk pays for the
//! maximum row count and stack multiplexing on every proof, even for trivial
//! scripts; increasing these constants is a protocol/circuit sizing decision, not
//! a local refactor.

pub mod auth;
pub mod eval;
pub mod opcode;
pub mod timehash;

pub use eval::{
    evaluate, EvalContext, EvalError, EvalWitness, MultisigHook, MultisigWitness, SignatureHook,
    SignatureWitness,
};
pub use opcode::{predicate_root, predicate_root_domain, OpCode};

/// Fixed opcode rows per predicate script. Short scripts are right-padded with `NOP`.
pub const MAX_OPS: usize = 16;
/// Maximum witness stack depth during evaluation.
pub const STACK_DEPTH: usize = 16;
/// Maximum nested `IF` depth. This is separate from the value stack for clear errors.
pub const CONTROL_DEPTH: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fr_from_dec, fr_to_dec};
    use ark_bn254::Fr as Fr254;

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

    fn assert_eval_and_root(script: &[OpCode; MAX_OPS], want_result: bool, want_root: &str) {
        let got = evaluate(script, &EvalWitness::default(), &EvalContext::default())
            .expect("predicate evaluation must succeed");
        assert_eq!(got, want_result, "predicate boolean result drifted");
        assert_eq!(
            fr_to_dec(&predicate_root(script)),
            want_root,
            "predicate_root frozen vector drifted"
        );
    }

    fn assert_root(script: &[OpCode; MAX_OPS], want_root: &str) {
        assert_eq!(
            fr_to_dec(&predicate_root(script)),
            want_root,
            "predicate_root frozen vector drifted"
        );
    }

    #[test]
    fn less_than_matches_frozen_vector() {
        let script = padded(&[OpCode::Push(f(3)), OpCode::Push(f(7)), OpCode::LessThan]);
        assert_eval_and_root(
            &script,
            true,
            "10439131969717347927651508231569474620920245322596673762800947766534979949485",
        );
    }

    #[test]
    fn if_else_uses_masked_branch_selectors() {
        let script = padded(&[
            OpCode::Push(f(0)),
            OpCode::If,
            OpCode::Drop,
            OpCode::Else,
            OpCode::Push(f(22)),
            OpCode::EndIf,
            OpCode::Push(f(22)),
            OpCode::Equal,
        ]);
        assert_eval_and_root(
            &script,
            true,
            "20138044853533341619334017017147865014056172875633747455349000119132657881258",
        );
    }

    #[test]
    fn equalverify_success_matches_frozen_vector() {
        let script = padded(&[
            OpCode::Push(fr_from_dec("5")),
            OpCode::Push(fr_from_dec("5")),
            OpCode::EqualVerify,
            OpCode::Push(f(1)),
        ]);
        assert_eval_and_root(
            &script,
            true,
            "1421134807706671190262656328314495103494655891630769668295150009238200203341",
        );
    }

    #[test]
    fn equalverify_failure_fails_closed() {
        let script = padded(&[
            OpCode::Push(f(5)),
            OpCode::Push(f(6)),
            OpCode::EqualVerify,
            OpCode::Push(f(1)),
        ]);
        assert_root(
            &script,
            "9209459813019133608137498169654415581163675309895645198630920367486776517752",
        );
        assert!(
            matches!(
                evaluate(&script, &EvalWitness::default(), &EvalContext::default()),
                Err(EvalError::VerifyFailed(OpCode::EqualVerify))
            ),
            "EQUALVERIFY mismatch must abort, not false-pass"
        );
    }

    #[test]
    fn booland_of_two_comparisons_matches_frozen_vector() {
        let script = padded(&[
            OpCode::Push(f(1)),
            OpCode::Push(f(2)),
            OpCode::LessThan,
            OpCode::Push(f(10)),
            OpCode::Push(f(4)),
            OpCode::GreaterThan,
            OpCode::BoolAnd,
        ]);
        assert_eval_and_root(
            &script,
            true,
            "855408696787586656326946817003915100509506266918886906420094887706282190435",
        );
    }

    #[test]
    fn fail_closed_on_stack_underflow_and_unimplemented_opcode() {
        let underflow = padded(&[OpCode::Drop]);
        assert_root(
            &underflow,
            "21404224279979164462064956803546894650416117689231609547687425965741889489723",
        );
        assert!(
            matches!(
                evaluate(&underflow, &EvalWitness::default(), &EvalContext::default()),
                Err(EvalError::StackUnderflow {
                    opcode: OpCode::Drop,
                    needed: 1,
                    depth: 0,
                })
            ),
            "DROP on an empty stack must fail closed"
        );

        let reserved = padded(&[OpCode::CheckKyc]);
        assert_root(
            &reserved,
            "17229882187929689084271875439537553763017848081527243463799249839759506015377",
        );
        assert!(
            matches!(
                evaluate(&reserved, &EvalWitness::default(), &EvalContext::default()),
                Err(EvalError::Unimplemented(OpCode::CheckKyc))
            ),
            "reserved compliance opcodes must fail closed until implemented"
        );

        let inactive_reserved = padded(&[
            OpCode::Push(f(0)),
            OpCode::If,
            OpCode::CheckKyc,
            OpCode::EndIf,
            OpCode::Push(f(1)),
        ]);
        assert_root(
            &inactive_reserved,
            "14696560101327937132164114163234665907403836448132737002467070219774921798705",
        );
        assert!(
            matches!(
                evaluate(
                    &inactive_reserved,
                    &EvalWitness::default(),
                    &EvalContext::default()
                ),
                Err(EvalError::Unimplemented(OpCode::CheckKyc))
            ),
            "reserved opcodes must fail closed even under inactive branch selectors"
        );
    }
}
