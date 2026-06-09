//! Bounded, unrolled predicate evaluator.
//!
//! The evaluator deliberately has a fixed worst-case shape: it iterates exactly
//! [`MAX_OPS`] rows, has no program counter, and has no loops inside the user
//! script. This is the reference-oracle shape the UltraHonk circuit should mirror.
//!
//! Branching is selector-masked, not PC-driven. `IF` records a branch frame; every
//! row is still visited, but stack writes for rows whose branch selector is false
//! are no-ops. In-circuit this maps to computing the candidate next stack and then
//! applying `conditional_select(active, old, candidate)` for every stack lane,
//! using jf's convention that `conditional_select(b, A, B)` returns `A` when `b`
//! is false and `B` when `b` is true. Inactive branch rows therefore retain the
//! old stack state instead of silently succeeding with unconstrained effects.
//! Reserved/unimplemented opcodes are stricter: they fail closed anywhere in the
//! committed script, even under an inactive selector, until their constraints exist.

use super::{CONTROL_DEPTH, MAX_OPS, STACK_DEPTH};
use crate::Point;
use ark_bn254::Fr as Fr254;
use ark_ff::{One, PrimeField, Zero};

use super::opcode::OpCode;

/// Private predicate witness carried by the reference evaluator.
///
/// The foundation VM only consumes `initial_stack`; auth/hash/time extensions get
/// stable hook slots here so they can add constraints without changing the public
/// `evaluate(script, witness, ctx)` signature.
#[derive(Clone, Debug, Default)]
pub struct EvalWitness {
    /// Optional initial stack words, loaded bottom-to-top before row 0.
    pub initial_stack: Vec<Fr254>,
    /// Signature witnesses consumed by `CHECKSIG` / `CHECKDATASIG`.
    pub signatures: Vec<SignatureWitness>,
    /// Multisig witnesses consumed by `CHECKMULTISIG`.
    pub multisig: Vec<MultisigWitness>,
    /// Hash preimage openings consumed by future hash-lock opcodes.
    pub hash_preimages: Vec<Vec<Fr254>>,
}

/// Private signature material placeholder for `predvm-auth`.
#[derive(Clone, Debug, Default)]
pub struct SignatureWitness {
    /// Encoded signature scalars/points. The exact layout is owned by `predvm-auth`.
    pub fields: Vec<Fr254>,
}

/// Private multisig material placeholder for `predvm-auth`.
#[derive(Clone, Debug, Default)]
pub struct MultisigWitness {
    /// Encoded signature material for an m-of-n check.
    pub fields: Vec<Fr254>,
}

/// Public / statement-bound evaluation context.
///
/// `clock` and `sequence` are rollup-provided public inputs for CLTV/CSV. Signature
/// and covenant hook vectors are stable interface slots for downstream modules;
/// this foundation implementation fails closed before consuming them.
#[derive(Clone, Debug)]
pub struct EvalContext {
    /// Rollup-provided current block height/time for absolute timelocks.
    pub clock: Fr254,
    /// Rollup-provided relative age/sequence for CSV-style timelocks.
    pub sequence: Fr254,
    /// Public signature verification hooks consumed by `CHECKSIG` / `CHECKDATASIG`.
    pub signature_hooks: Vec<SignatureHook>,
    /// Public multisig verification hooks consumed by `CHECKMULTISIG`.
    pub multisig_hooks: Vec<MultisigHook>,
    /// Public output predicate roots available to covenant opcodes.
    pub output_predicate_roots: Vec<Fr254>,
    /// Public L1 state roots / commitments available to `CHECKL1STATE`.
    pub l1_state_roots: Vec<Fr254>,
}

impl Default for EvalContext {
    fn default() -> Self {
        Self {
            clock: Fr254::zero(),
            sequence: Fr254::zero(),
            signature_hooks: Vec::new(),
            multisig_hooks: Vec::new(),
            output_predicate_roots: Vec::new(),
            l1_state_roots: Vec::new(),
        }
    }
}

/// Public inputs for one signature check.
#[derive(Clone, Debug)]
pub struct SignatureHook {
    /// Baby JubJub public key expected to authorize the spend or data message.
    pub public_key: Point,
    /// Field-framed message transcript. Downstream auth must domain-separate it.
    pub message: Vec<Fr254>,
}

/// Public inputs for one multisig check.
#[derive(Clone, Debug)]
pub struct MultisigHook {
    /// Number of valid signatures required.
    pub threshold: usize,
    /// Candidate Baby JubJub public keys.
    pub public_keys: Vec<Point>,
    /// Field-framed message transcript. Downstream auth must domain-separate it.
    pub message: Vec<Fr254>,
}

/// Fail-closed evaluator errors. No opcode has a default-true path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    /// Attempted to pop more words than the bounded stack currently contains.
    StackUnderflow {
        opcode: OpCode,
        needed: usize,
        depth: usize,
    },
    /// Attempted to exceed [`STACK_DEPTH`].
    StackOverflow { opcode: OpCode, depth: usize },
    /// Nested branches exceeded [`CONTROL_DEPTH`].
    ControlStackOverflow { opcode: OpCode, depth: usize },
    /// `ELSE` / `ENDIF` appeared without a matching `IF`, or `ELSE` appeared twice.
    ControlFlowMismatch { opcode: OpCode },
    /// Script ended before all `IF` frames were closed.
    UnbalancedControlFlow { depth: usize },
    /// `EQUALVERIFY` failed.
    VerifyFailed(OpCode),
    /// A protocol opcode is reserved but not implemented by this foundation module.
    Unimplemented(OpCode),
    /// The script completed without a boolean result on the stack.
    EmptyFinalStack,
}

impl core::fmt::Display for EvalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EvalError {}

#[derive(Clone, Copy, Debug)]
struct BranchFrame {
    parent_active: bool,
    condition: bool,
    in_else: bool,
}

#[derive(Clone, Debug)]
struct ControlStack {
    frames: [BranchFrame; CONTROL_DEPTH],
    depth: usize,
}

impl Default for ControlStack {
    fn default() -> Self {
        Self {
            frames: [BranchFrame {
                parent_active: true,
                condition: false,
                in_else: false,
            }; CONTROL_DEPTH],
            depth: 0,
        }
    }
}

impl ControlStack {
    fn active(&self) -> bool {
        if self.depth == 0 {
            true
        } else {
            let top = self.frames[self.depth - 1];
            top.parent_active
                && if top.in_else {
                    !top.condition
                } else {
                    top.condition
                }
        }
    }

    fn push(
        &mut self,
        opcode: OpCode,
        parent_active: bool,
        condition: bool,
    ) -> Result<(), EvalError> {
        if self.depth == CONTROL_DEPTH {
            return Err(EvalError::ControlStackOverflow {
                opcode,
                depth: self.depth,
            });
        }
        self.frames[self.depth] = BranchFrame {
            parent_active,
            condition,
            in_else: false,
        };
        self.depth += 1;
        Ok(())
    }

    fn flip_else(&mut self, opcode: OpCode) -> Result<(), EvalError> {
        if self.depth == 0 {
            return Err(EvalError::ControlFlowMismatch { opcode });
        }
        let top = &mut self.frames[self.depth - 1];
        if top.in_else {
            return Err(EvalError::ControlFlowMismatch { opcode });
        }
        top.in_else = true;
        Ok(())
    }

    fn pop(&mut self, opcode: OpCode) -> Result<(), EvalError> {
        if self.depth == 0 {
            return Err(EvalError::ControlFlowMismatch { opcode });
        }
        self.depth -= 1;
        Ok(())
    }
}

/// Bounded evaluation value stack.
///
/// Exposed to sibling opcode modules (`auth`, `timehash`) at crate visibility so
/// they can implement their arms without re-deriving stack discipline. The slot
/// array stays private; mutation only happens through the checked `push`/`pop`
/// helpers so the fixed-depth invariants and fail-closed underflow/overflow errors
/// are enforced in one place.
#[derive(Clone, Debug)]
pub(crate) struct Stack {
    slots: [Fr254; STACK_DEPTH],
    depth: usize,
}

impl Stack {
    fn new(witness: &EvalWitness) -> Result<Self, EvalError> {
        if witness.initial_stack.len() > STACK_DEPTH {
            return Err(EvalError::StackOverflow {
                opcode: OpCode::Nop,
                depth: witness.initial_stack.len(),
            });
        }
        let mut slots = [Fr254::zero(); STACK_DEPTH];
        for (i, v) in witness.initial_stack.iter().enumerate() {
            slots[i] = *v;
        }
        Ok(Self {
            slots,
            depth: witness.initial_stack.len(),
        })
    }

    pub(crate) fn push(&mut self, opcode: OpCode, value: Fr254) -> Result<(), EvalError> {
        if self.depth == STACK_DEPTH {
            return Err(EvalError::StackOverflow {
                opcode,
                depth: self.depth,
            });
        }
        self.slots[self.depth] = value;
        self.depth += 1;
        Ok(())
    }

    pub(crate) fn pop(&mut self, opcode: OpCode) -> Result<Fr254, EvalError> {
        if self.depth == 0 {
            return Err(EvalError::StackUnderflow {
                opcode,
                needed: 1,
                depth: 0,
            });
        }
        self.depth -= 1;
        Ok(self.slots[self.depth])
    }

    pub(crate) fn pop2(&mut self, opcode: OpCode) -> Result<(Fr254, Fr254), EvalError> {
        if self.depth < 2 {
            return Err(EvalError::StackUnderflow {
                opcode,
                needed: 2,
                depth: self.depth,
            });
        }
        let rhs = self.pop(opcode)?;
        let lhs = self.pop(opcode)?;
        Ok((lhs, rhs))
    }

    pub(crate) fn peek(&self) -> Result<Fr254, EvalError> {
        if self.depth == 0 {
            return Err(EvalError::EmptyFinalStack);
        }
        Ok(self.slots[self.depth - 1])
    }
}

/// jf-style conditional select: returns `a` when `b == false`, `t` when `b == true`.
fn cs(b: bool, a: Fr254, t: Fr254) -> Fr254 {
    if b {
        t
    } else {
        a
    }
}

pub(crate) fn bool_field(b: bool) -> Fr254 {
    if b {
        Fr254::one()
    } else {
        Fr254::zero()
    }
}

pub(crate) fn truthy(v: Fr254) -> bool {
    !v.is_zero()
}

pub(crate) fn canonical_lt(lhs: Fr254, rhs: Fr254) -> bool {
    lhs.into_bigint() < rhs.into_bigint()
}

/// Covenant / compliance / L1 opcodes that have no constraints yet. These fail
/// closed anywhere in a committed script, even under an inactive branch selector,
/// so a script can never silently commit to behaviour the circuit cannot enforce.
///
/// Auth (`CHECKSIG`/`CHECKMULTISIG`/`CHECKDATASIG`) and time/hash
/// (`HASH`/`CLTV`/`CSV`) opcodes are owned by the `auth` and `timehash` modules;
/// their reserved state lives in [`super::auth::is_reserved`] /
/// [`super::timehash::is_reserved`] so those modules can lift the fail-closed trap
/// the moment they add real constraints, without editing this list.
fn is_unimplemented_opcode(opcode: OpCode) -> bool {
    matches!(
        opcode,
        OpCode::CheckOutputPredicate
            | OpCode::CheckRecipient
            | OpCode::CheckAmount
            | OpCode::InspectValue
            | OpCode::CheckKyc
            | OpCode::CheckNotRevoked
            | OpCode::CheckNotSanctioned
            | OpCode::CheckKycTier
            | OpCode::CheckJurisdiction
            | OpCode::Audit
            | OpCode::CheckL1State
    )
}

fn execute_active(
    opcode: OpCode,
    stack: &mut Stack,
    witness: &EvalWitness,
    ctx: &EvalContext,
) -> Result<(), EvalError> {
    match opcode {
        OpCode::Nop => Ok(()),
        OpCode::Push(value) => stack.push(opcode, value),
        OpCode::Dup => {
            let value = stack.pop(opcode)?;
            stack.push(opcode, value)?;
            stack.push(opcode, value)
        }
        OpCode::Drop => stack.pop(opcode).map(|_| ()),
        OpCode::Swap => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, rhs)?;
            stack.push(opcode, lhs)
        }
        OpCode::Equal => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, bool_field(lhs == rhs))
        }
        OpCode::EqualVerify => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            if lhs == rhs {
                Ok(())
            } else {
                Err(EvalError::VerifyFailed(opcode))
            }
        }
        OpCode::LessThan => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, bool_field(canonical_lt(lhs, rhs)))
        }
        OpCode::GreaterThan => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, bool_field(canonical_lt(rhs, lhs)))
        }
        OpCode::BoolAnd => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, bool_field(truthy(lhs) && truthy(rhs)))
        }
        OpCode::BoolOr => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, bool_field(truthy(lhs) || truthy(rhs)))
        }
        OpCode::Add => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, lhs + rhs)
        }
        OpCode::Sub => {
            let (lhs, rhs) = stack.pop2(opcode)?;
            stack.push(opcode, lhs - rhs)
        }
        OpCode::If | OpCode::Else | OpCode::EndIf => Err(EvalError::ControlFlowMismatch { opcode }),
        OpCode::CheckSig | OpCode::CheckMultiSig | OpCode::CheckDataSig => {
            // Owned by `predvm-auth`; see `super::auth::execute`.
            super::auth::execute(opcode, stack, witness, ctx)
        }
        OpCode::Hash | OpCode::CheckLockTimeVerify | OpCode::CheckSequenceVerify => {
            // Owned by `predvm-time-hash`; see `super::timehash::execute`.
            super::timehash::execute(opcode, stack, witness, ctx)
        }
        OpCode::CheckOutputPredicate
        | OpCode::CheckRecipient
        | OpCode::CheckAmount
        | OpCode::InspectValue
        | OpCode::CheckKyc
        | OpCode::CheckNotRevoked
        | OpCode::CheckNotSanctioned
        | OpCode::CheckKycTier
        | OpCode::CheckJurisdiction
        | OpCode::Audit
        | OpCode::CheckL1State => Err(EvalError::Unimplemented(opcode)),
    }
}

/// Evaluate a fixed-size predicate script against its private witness and context.
pub fn evaluate(
    script: &[OpCode; MAX_OPS],
    witness: &EvalWitness,
    ctx: &EvalContext,
) -> Result<bool, EvalError> {
    let mut stack = Stack::new(witness)?;
    let mut control = ControlStack::default();

    for opcode in script.iter().copied() {
        match opcode {
            OpCode::If => {
                let parent_active = control.active();
                let condition = if parent_active {
                    truthy(stack.pop(opcode)?)
                } else {
                    false
                };
                control.push(opcode, parent_active, condition)?;
            }
            OpCode::Else => control.flip_else(opcode)?,
            OpCode::EndIf => control.pop(opcode)?,
            _ => {
                if is_unimplemented_opcode(opcode)
                    || super::auth::is_reserved(opcode)
                    || super::timehash::is_reserved(opcode)
                {
                    // Reserved rows fail closed even under an inactive branch. Until
                    // their constraints exist, allowing them anywhere in a committed
                    // script would create a silent compatibility/soundness trap. Each
                    // opcode family owns its reserved flag, so implementing a family
                    // lifts only its own trap.
                    execute_active(opcode, &mut stack, witness, ctx)?;
                }

                let active = control.active();
                if active {
                    execute_active(opcode, &mut stack, witness, ctx)?;
                } else {
                    // Circuit mirror: every lane keeps its old value when the row's
                    // branch selector is false: cs(active, old, candidate) == old.
                    for slot in stack.slots.iter_mut() {
                        *slot = cs(false, *slot, Fr254::zero());
                    }
                }
            }
        }
    }

    if control.depth != 0 {
        return Err(EvalError::UnbalancedControlFlow {
            depth: control.depth,
        });
    }

    Ok(truthy(stack.peek()?))
}
