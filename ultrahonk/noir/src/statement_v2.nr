//! Programmable-note v2 transfer statement.
//!
//! This is the Noir mirror of the frozen Rust oracle in
//! `ultrahonk/rust/src/statement_v2.rs`.  The adversary controls every witness
//! field, so the circuit reconstructs the committed notes, evaluates and binds the
//! predicates, proves membership, enforces per-asset conservation, and derives
//! nullifiers only from the one-time spend secret constrained to the committed
//! one-time public key.

use crate::bjj;
use crate::bjj::Point;
use crate::hash;
use crate::keys;
use crate::merkle::{compute_root, PathElement};
use crate::notev2;
use crate::script;

/// Number of spent notes in the fixed v2 transfer shape.
pub global N_IN: u32 = 2;
/// Number of created notes in the fixed v2 transfer shape.
pub global N_OUT: u32 = 2;
/// Test-vector Merkle depth.  The frozen Rust v2 transfer anchors two leaves.
pub global DEPTH_V2: u32 = 1;
/// Framed public inputs: `[domain, root, nf_0, nf_1, out_0, out_1]`.
pub global NUM_PUBLIC_INPUTS_V2: u32 = 6;
/// `Fr::from_le_bytes_mod_order(b"NF4_STATEMENT_V2_TRANSFER")`.
pub global PUBLIC_INPUTS_FRAMING_V2: Field =
    516420953215171890327788881277379126594098488104739946120782;

/// Reconstructable v2 note preimage shared by inputs and outputs.
pub struct StatementV2Note {
    pub asset_class_tag: Field,
    pub token_contract: Field,
    pub slot_id: Field,
    pub predicate_root: Field,
    pub value: Field,
    pub pk_onetime: Point,
    pub salt: Field,
    pub mode_tag: Field,
}

/// Private witness for one spent v2 note.
pub struct StatementV2InputNote {
    pub note: StatementV2Note,
    pub script: [script::OpCode; script::MAX_OPS],
    pub eval_witness: script::EvalWitness,
    pub eval_ctx: script::EvalContext,
    pub onetime_secret: Field,
    pub membership_proof: [PathElement; DEPTH_V2],
}

/// Private witness for one created v2 note.
pub struct StatementV2OutputNote {
    pub note: StatementV2Note,
}

/// Full witness for the fixed 2-in/2-out programmable-note transfer statement.
pub struct StatementV2Inputs {
    pub root: Field,
    pub inputs: [StatementV2InputNote; N_IN],
    pub outputs: [StatementV2OutputNote; N_OUT],
}

fn points_equal(a: Point, b: Point) -> bool {
    (a.x == b.x) & (a.y == b.y)
}

fn opcode_equal(a: script::OpCode, b: script::OpCode) -> bool {
    (a.tag == b.tag) & (a.immediate == b.immediate)
}

fn canonical_ownership_script() -> [script::OpCode; script::MAX_OPS] {
    let mut program: [script::OpCode; script::MAX_OPS] = [script::nop(); script::MAX_OPS];
    program[0] = script::push(0);
    program[1] = script::OpCode { tag: script::TAG_CHECKSIG, immediate: 0 };
    program
}

fn script_uses_checksig(program: [script::OpCode; script::MAX_OPS]) -> bool {
    let mut uses = false;
    for i in 0..script::MAX_OPS {
        uses = uses | (program[i].tag == script::TAG_CHECKSIG);
    }
    uses
}

fn is_canonical_ownership(program: [script::OpCode; script::MAX_OPS]) -> bool {
    let canonical = canonical_ownership_script();
    let mut ok = true;
    for i in 0..script::MAX_OPS {
        ok = ok & opcode_equal(program[i], canonical[i]);
    }
    ok
}

fn note_asset_id(note: StatementV2Note) -> Field {
    notev2::asset_id(note.asset_class_tag, note.token_contract, note.slot_id, note.predicate_root)
}

fn note_commitment(note: StatementV2Note) -> Field {
    let asset = note_asset_id(note);
    notev2::commitment_v2(asset, note.value, note.pk_onetime, note.salt, note.mode_tag)
}

fn assert_owner_binding(input: StatementV2InputNote) {
    if script_uses_checksig(input.script) {
        if is_canonical_ownership(input.script) {
            assert(input.eval_ctx.signature_hook_count == 1, "statement_v2: canonical ownership hook count mismatch");
        }
        for i in 0..script::MAX_HOOKS {
            if i < input.eval_ctx.signature_hook_count {
                let hook = input.eval_ctx.signature_hooks[i];
                assert(points_equal(hook.public_key, input.note.pk_onetime), "statement_v2: owner-binding violation");
            }
        }
    }
}

fn assert_predicate(input: StatementV2InputNote) {
    assert(input.note.predicate_root == script::predicate_root(input.script), "statement_v2: predicate root mismatch");
    assert_owner_binding(input);
    assert(script::evaluate(input.script, input.eval_witness, input.eval_ctx), "statement_v2: predicate evaluation failed");
}

fn input_nullifier_key(input: StatementV2InputNote) -> Field {
    bjj::assert_valid_scalar(input.onetime_secret);
    assert(input.onetime_secret != 0, "statement_v2: one-time key binding violation");
    let opened = bjj::mul_by_generator(input.onetime_secret);
    assert(points_equal(opened, input.note.pk_onetime), "statement_v2: one-time key binding violation");
    keys::nullifier_key(input.onetime_secret)
}

fn value_sum_for_asset(
    asset: Field,
    assets: [Field; N_IN],
    values: [Field; N_IN],
) -> Field {
    let mut sum = 0;
    for i in 0..N_IN {
        if assets[i] == asset {
            sum += values[i];
        }
    }
    sum
}

fn output_sum_for_asset(
    asset: Field,
    assets: [Field; N_OUT],
    values: [Field; N_OUT],
) -> Field {
    let mut sum = 0;
    for i in 0..N_OUT {
        if assets[i] == asset {
            sum += values[i];
        }
    }
    sum
}

fn assert_value_conservation(
    input_assets: [Field; N_IN],
    input_values: [Field; N_IN],
    output_assets: [Field; N_OUT],
    output_values: [Field; N_OUT],
) {
    for i in 0..N_IN {
        let asset = input_assets[i];
        assert(
            value_sum_for_asset(asset, input_assets, input_values)
                == output_sum_for_asset(asset, output_assets, output_values),
            "statement_v2: value conservation failed",
        );
    }
    for i in 0..N_OUT {
        let asset = output_assets[i];
        assert(
            value_sum_for_asset(asset, input_assets, input_values)
                == output_sum_for_asset(asset, output_assets, output_values),
            "statement_v2: value conservation failed",
        );
    }
}

fn assert_no_duplicate_nonzero<let N: u32>(values: [Field; N], label: Field) {
    for i in 0..N {
        for j in (i + 1)..N {
            assert((values[j] == 0) | (values[j] != values[i]), "statement_v2: duplicate nonzero public output");
        }
    }
    let _ = label;
}

/// Run the fixed v2 transfer statement and return the framed public-input vector.
pub fn prove_statement_v2(inp: StatementV2Inputs) -> [Field; NUM_PUBLIC_INPUTS_V2] {
    for i in 0..N_IN {
        inp.inputs[i].note.value.assert_max_bit_size::<96>();
        assert_predicate(inp.inputs[i]);
    }
    for i in 0..N_OUT {
        inp.outputs[i].note.value.assert_max_bit_size::<96>();
    }

    let mut input_assets: [Field; N_IN] = [0; N_IN];
    let mut input_values: [Field; N_IN] = [0; N_IN];
    let mut input_commitments: [Field; N_IN] = [0; N_IN];
    for i in 0..N_IN {
        input_assets[i] = note_asset_id(inp.inputs[i].note);
        input_values[i] = inp.inputs[i].note.value;
        input_commitments[i] = note_commitment(inp.inputs[i].note);
        assert(compute_root(input_commitments[i], inp.inputs[i].membership_proof) == inp.root, "statement_v2: membership proof failed");
    }

    let mut output_assets: [Field; N_OUT] = [0; N_OUT];
    let mut output_values: [Field; N_OUT] = [0; N_OUT];
    let mut output_commitments: [Field; N_OUT] = [0; N_OUT];
    for i in 0..N_OUT {
        output_assets[i] = note_asset_id(inp.outputs[i].note);
        output_values[i] = inp.outputs[i].note.value;
        output_commitments[i] = note_commitment(inp.outputs[i].note);
    }

    assert_value_conservation(input_assets, input_values, output_assets, output_values);

    let mut nullifiers: [Field; N_IN] = [0; N_IN];
    for i in 0..N_IN {
        let nf_key = input_nullifier_key(inp.inputs[i]);
        nullifiers[i] = hash::hash2(nf_key, input_commitments[i]);
    }

    assert_no_duplicate_nonzero(nullifiers, 0);
    assert_no_duplicate_nonzero(output_commitments, 1);

    [
        PUBLIC_INPUTS_FRAMING_V2,
        inp.root,
        nullifiers[0],
        nullifiers[1],
        output_commitments[0],
        output_commitments[1],
    ]
}
