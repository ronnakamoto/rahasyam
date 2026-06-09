//! Bounded predicate-VM mirror for `ultrahonk/rust/src/predvm/`.
//!
//! Scripts are fixed `[OpCode; MAX_OPS]` arrays, padded with `NOP`, and the
//! evaluator visits every row.  Authentication opcodes fail closed unless their
//! Baby-JubJub Schnorr equation verifies against the statement-bound hook.

use crate::bjj;
use crate::bjj::Point;
use crate::sponge;
use poseidon::poseidon::bn254::perm;

/// Fixed predicate rows. Short scripts are right-padded with `NOP`.
pub global MAX_OPS: u32 = 16;
/// Bounded witness stack depth.
pub global STACK_DEPTH: u32 = 16;
/// Bounded nested `IF` depth.
pub global CONTROL_DEPTH: u32 = 8;
/// Root preimage words: domain + MAX_OPS + `(tag, immediate) * MAX_OPS`.
pub global ROOT_WORDS: u32 = 34;
/// Bounded hook count for auth/time/hash extension modules.
pub global MAX_HOOKS: u32 = 4;
/// Bounded auth-message length for Noir's fixed-size mirror of Rust `Vec<Fr254>`.
pub global MAX_MESSAGE_LEN: u32 = 8;
/// `Fr254::from_le_bytes_mod_order(b"PREDVM_ROOT_V1")`.
pub global PREDICATE_ROOT_DOMAIN: Field = 1000681195555390639693231454245456;
/// `Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKSIG_V1")`.
pub global CHECKSIG_DOMAIN: Field = 4297892941011344447779307482803189917766224;
/// Same BN254 -> BJJ no-wrap guard used by `keys.nr`.
global NO_WRAP_BOUND: Field =
    2736030358979909402780800718157159386010666595306063529296694559936676884330;

pub global TAG_NOP: Field = 0;
pub global TAG_PUSH: Field = 1;
pub global TAG_DUP: Field = 2;
pub global TAG_DROP: Field = 3;
pub global TAG_SWAP: Field = 4;
pub global TAG_EQUAL: Field = 5;
pub global TAG_EQUALVERIFY: Field = 6;
pub global TAG_LESSTHAN: Field = 7;
pub global TAG_GREATERTHAN: Field = 8;
pub global TAG_BOOLAND: Field = 9;
pub global TAG_BOOLOR: Field = 10;
pub global TAG_ADD: Field = 11;
pub global TAG_SUB: Field = 12;
pub global TAG_IF: Field = 13;
pub global TAG_ELSE: Field = 14;
pub global TAG_ENDIF: Field = 15;
pub global TAG_CHECKSIG: Field = 16;
pub global TAG_CHECKMULTISIG: Field = 17;
pub global TAG_HASH: Field = 18;
pub global TAG_CHECKLOCKTIMEVERIFY: Field = 19;
pub global TAG_CHECKSEQUENCEVERIFY: Field = 20;
pub global TAG_CHECKDATASIG: Field = 21;
pub global TAG_CHECKOUTPUTPREDICATE: Field = 22;
pub global TAG_CHECKRECIPIENT: Field = 23;
pub global TAG_CHECKAMOUNT: Field = 24;
pub global TAG_INSPECTVALUE: Field = 25;
pub global TAG_CHECKKYC: Field = 26;
pub global TAG_CHECKNOTREVOKED: Field = 27;
pub global TAG_CHECKNOTSANCTIONED: Field = 28;
pub global TAG_CHECKKYCTIER: Field = 29;
pub global TAG_CHECKJURISDICTION: Field = 30;
pub global TAG_AUDIT: Field = 31;
pub global TAG_CHECKL1STATE: Field = 32;

/// Encoded opcode row. `immediate` is non-zero only for `PUSH`.
pub struct OpCode {
    pub tag: Field,
    pub immediate: Field,
}

/// Private signature witness: `[R.x, R.y, z, c, lambda]`.
/// `c + lambda * L == H(domain, pk, R, len, message)` constrains the Rust
/// `BjjFr::from_be_bytes_mod_order` challenge reduction.
pub struct SignatureWitness {
    pub fields: [Field; 5],
}

/// Private multisig witness placeholder owned by `predvm-auth`.
pub struct MultisigWitness {
    pub fields: [Field; 8],
}

/// Private evaluator witness.
pub struct EvalWitness {
    pub initial_stack: [Field; STACK_DEPTH],
    pub initial_depth: u32,
    pub signatures: [SignatureWitness; MAX_HOOKS],
    pub signature_count: u32,
    pub multisig: [MultisigWitness; MAX_HOOKS],
    pub hash_preimages: [[Field; 4]; MAX_HOOKS],
}

/// Public inputs for one signature check.
pub struct SignatureHook {
    pub public_key: Point,
    pub message: [Field; MAX_MESSAGE_LEN],
    pub message_len: u32,
}

/// Public inputs for one multisig check.
pub struct MultisigHook {
    pub threshold: u32,
    pub public_keys: [Point; MAX_HOOKS],
    pub message: [Field; MAX_MESSAGE_LEN],
    pub message_len: u32,
}

/// Public / statement-bound context for extension opcodes.
pub struct EvalContext {
    pub clock: Field,
    pub sequence: Field,
    pub signature_hooks: [SignatureHook; MAX_HOOKS],
    pub signature_hook_count: u32,
    pub multisig_hooks: [MultisigHook; MAX_HOOKS],
    pub output_predicate_roots: [Field; MAX_HOOKS],
    pub l1_state_roots: [Field; MAX_HOOKS],
}

/// jf-style conditional select: `a` when `b` is false, `t` when true.
fn cs(b: bool, a: Field, t: Field) -> Field {
    if b { t } else { a }
}

fn truthy(x: Field) -> bool {
    x != 0
}

fn bool_field(b: bool) -> Field {
    if b { 1 } else { 0 }
}

fn points_equal(a: Point, b: Point) -> bool {
    (a.x == b.x) & (a.y == b.y)
}

pub fn nop() -> OpCode {
    OpCode { tag: TAG_NOP, immediate: 0 }
}

pub fn push(value: Field) -> OpCode {
    OpCode { tag: TAG_PUSH, immediate: value }
}

/// Compute the note-bound script commitment using the Rust v1 encoding.
pub fn predicate_root(script: [OpCode; MAX_OPS]) -> Field {
    let mut words: [Field; ROOT_WORDS] = [0; ROOT_WORDS];
    words[0] = PREDICATE_ROOT_DOMAIN;
    words[1] = MAX_OPS as Field;
    for i in 0..MAX_OPS {
        words[2 + (2 * i)] = script[i].tag;
        words[3 + (2 * i)] = script[i].immediate;
    }
    sponge::hash(words)
}

fn push_stack(stack: [Field; STACK_DEPTH], depth: u32, value: Field) -> ([Field; STACK_DEPTH], u32) {
    assert(depth < STACK_DEPTH, "predvm: stack overflow");
    let mut out = stack;
    out[depth] = value;
    (out, depth + 1)
}

fn pop_stack(stack: [Field; STACK_DEPTH], depth: u32) -> ([Field; STACK_DEPTH], u32, Field) {
    assert(depth > 0, "predvm: stack underflow");
    (stack, depth - 1, stack[depth - 1])
}

fn active_at(
    control_parent: [bool; CONTROL_DEPTH],
    control_cond: [bool; CONTROL_DEPTH],
    control_else: [bool; CONTROL_DEPTH],
    control_depth: u32,
) -> bool {
    if control_depth == 0 {
        true
    } else {
        let top = control_depth - 1;
        control_parent[top] & if control_else[top] { !control_cond[top] } else { control_cond[top] }
    }
}

fn field_to_hook_index(v: Field) -> u32 {
    v.assert_max_bit_size::<32>();
    let idx = v as u32;
    assert(idx < MAX_HOOKS, "predvm: auth hook index out of range");
    idx
}

fn challenge_word(
    domain: Field,
    pk: Point,
    r_point: Point,
    message: [Field; MAX_MESSAGE_LEN],
    message_len: u32,
    idx: u32,
) -> Field {
    if idx == 0 {
        domain
    } else if idx == 1 {
        pk.x
    } else if idx == 2 {
        pk.y
    } else if idx == 3 {
        r_point.x
    } else if idx == 4 {
        r_point.y
    } else if idx == 5 {
        message_len as Field
    } else {
        let pos = idx - 6;
        let mut out = 0;
        for i in 0..MAX_MESSAGE_LEN {
            if pos == i {
                out = message[i];
            }
        }
        out
    }
}

fn challenge_hash(
    domain: Field,
    pk: Point,
    r_point: Point,
    message: [Field; MAX_MESSAGE_LEN],
    message_len: u32,
) -> Field {
    assert(message_len <= MAX_MESSAGE_LEN, "predvm: message too long");
    let total = 6 + message_len;
    let mut state: [Field; 4] = [0; 4];
    for c in 0..5 {
        for k in 0..3 {
            let idx = c * 3 + k;
            if idx < total {
                state[1 + k] += challenge_word(domain, pk, r_point, message, message_len, idx);
            }
        }
        if (c * 3) < total {
            state = perm::x5_4(state);
        }
    }
    state[0]
}

fn constrain_bjj_reduction(hash_value: Field, scalar: Field, lambda: Field) -> Field {
    assert(scalar + lambda * bjj::SUBGROUP_ORDER == hash_value, "predvm: challenge reduction mismatch");
    bjj::assert_valid_scalar(scalar);
    assert(lambda.lt(8), "predvm: challenge quotient out of range");
    let guarded = if lambda == 7 { scalar } else { 0 };
    assert(guarded.lt(NO_WRAP_BOUND), "predvm: challenge reduction wraps the field modulus");
    scalar
}

fn verify_schnorr(
    domain: Field,
    pk: Point,
    message: [Field; MAX_MESSAGE_LEN],
    message_len: u32,
    sig: SignatureWitness,
) -> bool {
    assert(!bjj::is_neutral(pk), "predvm: neutral public key");
    bjj::assert_in_subgroup(pk);
    let r_point = Point { x: sig.fields[0], y: sig.fields[1] };
    assert(!bjj::is_neutral(r_point), "predvm: neutral nonce point");
    bjj::assert_in_subgroup(r_point);
    let z = sig.fields[2];
    bjj::assert_valid_scalar(z);
    let h = challenge_hash(domain, pk, r_point, message, message_len);
    let c = constrain_bjj_reduction(h, sig.fields[3], sig.fields[4]);

    let lhs = bjj::mul_by_generator(z);
    let rhs = bjj::add(r_point, bjj::scalar_mul(c, pk));
    points_equal(lhs, rhs)
}

fn op_checksig(
    stack: [Field; STACK_DEPTH],
    depth: u32,
    witness: EvalWitness,
    ctx: EvalContext,
) -> ([Field; STACK_DEPTH], u32) {
    assert(witness.signature_count <= MAX_HOOKS, "predvm: signature witness overflow");
    assert(ctx.signature_hook_count <= MAX_HOOKS, "predvm: signature hook overflow");
    let popped = pop_stack(stack, depth);
    let idx = field_to_hook_index(popped.2);
    assert(idx < witness.signature_count, "predvm: missing signature witness");
    assert(idx < ctx.signature_hook_count, "predvm: missing signature hook");
    let hook = ctx.signature_hooks[idx];
    let sig = witness.signatures[idx];
    let ok = verify_schnorr(CHECKSIG_DOMAIN, hook.public_key, hook.message, hook.message_len, sig);
    push_stack(popped.0, popped.1, bool_field(ok))
}

/// Evaluate the bounded predicate.
pub fn evaluate(script: [OpCode; MAX_OPS], witness: EvalWitness, ctx: EvalContext) -> bool {
    assert(witness.initial_depth <= STACK_DEPTH, "predvm: initial stack overflow");

    let mut stack = witness.initial_stack;
    let mut depth = witness.initial_depth;
    let mut control_parent: [bool; CONTROL_DEPTH] = [false; CONTROL_DEPTH];
    let mut control_cond: [bool; CONTROL_DEPTH] = [false; CONTROL_DEPTH];
    let mut control_else: [bool; CONTROL_DEPTH] = [false; CONTROL_DEPTH];
    let mut control_depth: u32 = 0;

    for pc in 0..MAX_OPS {
        let op = script[pc];

        if op.tag == TAG_IF {
            let parent_active = active_at(control_parent, control_cond, control_else, control_depth);
            let mut cond = false;
            if parent_active {
                let popped = pop_stack(stack, depth);
                stack = popped.0;
                depth = popped.1;
                cond = truthy(popped.2);
            }
            assert(control_depth < CONTROL_DEPTH, "predvm: control stack overflow");
            control_parent[control_depth] = parent_active;
            control_cond[control_depth] = cond;
            control_else[control_depth] = false;
            control_depth += 1;
        } else if op.tag == TAG_ELSE {
            assert(control_depth > 0, "predvm: ELSE without IF");
            let top = control_depth - 1;
            assert(!control_else[top], "predvm: duplicate ELSE");
            control_else[top] = true;
        } else if op.tag == TAG_ENDIF {
            assert(control_depth > 0, "predvm: ENDIF without IF");
            control_depth -= 1;
        } else {
            let unimplemented = (op.tag == TAG_CHECKMULTISIG)
                | (op.tag == TAG_HASH)
                | (op.tag == TAG_CHECKLOCKTIMEVERIFY)
                | (op.tag == TAG_CHECKSEQUENCEVERIFY)
                | (op.tag == TAG_CHECKDATASIG)
                | (op.tag == TAG_CHECKOUTPUTPREDICATE)
                | (op.tag == TAG_CHECKRECIPIENT)
                | (op.tag == TAG_CHECKAMOUNT)
                | (op.tag == TAG_INSPECTVALUE)
                | (op.tag == TAG_CHECKKYC)
                | (op.tag == TAG_CHECKNOTREVOKED)
                | (op.tag == TAG_CHECKNOTSANCTIONED)
                | (op.tag == TAG_CHECKKYCTIER)
                | (op.tag == TAG_CHECKJURISDICTION)
                | (op.tag == TAG_AUDIT)
                | (op.tag == TAG_CHECKL1STATE);
            assert(!unimplemented, "predvm: reserved opcode unimplemented");

            let active = active_at(control_parent, control_cond, control_else, control_depth);
            if active {
                if op.tag == TAG_NOP {
                    // no-op
                } else if op.tag == TAG_PUSH {
                    let pushed = push_stack(stack, depth, op.immediate);
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_DUP {
                    assert(depth > 0, "predvm: DUP underflow");
                    let pushed = push_stack(stack, depth, stack[depth - 1]);
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_DROP {
                    let popped = pop_stack(stack, depth);
                    stack = popped.0;
                    depth = popped.1;
                } else if op.tag == TAG_SWAP {
                    assert(depth >= 2, "predvm: SWAP underflow");
                    let a = stack[depth - 2];
                    let b = stack[depth - 1];
                    stack[depth - 2] = b;
                    stack[depth - 1] = a;
                } else if op.tag == TAG_EQUAL {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, bool_field(lhs.2 == rhs.2));
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_EQUALVERIFY {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    assert(lhs.2 == rhs.2, "predvm: EQUALVERIFY failed");
                } else if op.tag == TAG_LESSTHAN {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, bool_field(lhs.2.lt(rhs.2)));
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_GREATERTHAN {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, bool_field(rhs.2.lt(lhs.2)));
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_BOOLAND {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, bool_field(truthy(lhs.2) & truthy(rhs.2)));
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_BOOLOR {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, bool_field(truthy(lhs.2) | truthy(rhs.2)));
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_ADD {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, lhs.2 + rhs.2);
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_SUB {
                    let rhs = pop_stack(stack, depth);
                    stack = rhs.0;
                    depth = rhs.1;
                    let lhs = pop_stack(stack, depth);
                    stack = lhs.0;
                    depth = lhs.1;
                    let pushed = push_stack(stack, depth, lhs.2 - rhs.2);
                    stack = pushed.0;
                    depth = pushed.1;
                } else if op.tag == TAG_CHECKSIG {
                    let checked = op_checksig(stack, depth, witness, ctx);
                    stack = checked.0;
                    depth = checked.1;
                } else {
                    assert(false, "predvm: unknown opcode");
                }
            } else {
                for i in 0..STACK_DEPTH {
                    stack[i] = cs(false, stack[i], 0);
                }
            }
        }
    }

    assert(control_depth == 0, "predvm: unbalanced IF");
    assert(depth > 0, "predvm: empty final stack");
    truthy(stack[depth - 1])
}
