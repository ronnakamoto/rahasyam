//! Generate the programmable-note statement-v2 Noir parity vector.
//!
//! ```sh
//! cargo run --example gen_statement_v2
//! ```

use std::path::PathBuf;

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField, Zero};
use nf_curves::ed_on_bn254::Fr as BjjFr;
use nightfish_honk_ref::predvm::{EvalContext, EvalWitness, SignatureHook, SignatureWitness};
use nightfish_honk_ref::statement_v2::{
    canonical_ownership_script, compute_statement_v2, N_IN, N_OUT, StatementV2InputNote,
    StatementV2Inputs, StatementV2Note, StatementV2OutputNote,
};
use nightfish_honk_ref::{bjj, fr_to_dec, merkle, notev2, poseidon, sponge, Point};
use num_bigint::BigUint;

const MAX_MESSAGE_LEN: usize = 8;

fn f(v: u64) -> Fr254 {
    Fr254::from(v)
}

fn fdec(f: &Fr254) -> String {
    fr_to_dec(f)
}

fn bdec(s: &BjjFr) -> String {
    nightfish_honk_ref::bjj_to_dec(s)
}

fn point_nr(p: &Point) -> String {
    format!("Point {{ x: {}, y: {} }}", fdec(&p.x), fdec(&p.y))
}

fn checksig_domain() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKSIG_V1")
}

fn reduce_witness(h: Fr254) -> (Fr254, Fr254) {
    let h_big = BigUint::from_bytes_be(&h.into_bigint().to_bytes_be());
    let l_big = BigUint::from_bytes_be(&<BjjFr as PrimeField>::MODULUS.to_bytes_be());
    let c_big = &h_big % &l_big;
    let lambda_big = (&h_big - &c_big) / &l_big;
    (
        Fr254::from_le_bytes_mod_order(&c_big.to_bytes_le()),
        Fr254::from_le_bytes_mod_order(&lambda_big.to_bytes_le()),
    )
}

fn challenge_hash(domain: Fr254, pk: &Point, r_point: &Point, message: &[Fr254]) -> Fr254 {
    let mut transcript = Vec::with_capacity(6 + message.len());
    transcript.push(domain);
    transcript.push(pk.x);
    transcript.push(pk.y);
    transcript.push(r_point.x);
    transcript.push(r_point.y);
    transcript.push(Fr254::from(message.len() as u64));
    transcript.extend_from_slice(message);
    sponge::hash(&transcript)
}

fn sign(s: BjjFr, r: BjjFr, message: &[Fr254]) -> SignatureWitness {
    let pk = bjj::mul_by_generator(s);
    let r_point = bjj::mul_by_generator(r);
    let h = challenge_hash(checksig_domain(), &pk, &r_point, message);
    let (c_fr, _) = reduce_witness(h);
    let c = BjjFr::from_le_bytes_mod_order(&c_fr.into_bigint().to_bytes_le());
    let z = r + c * s;
    let z_fr = Fr254::from_le_bytes_mod_order(&z.into_bigint().to_bytes_le());
    SignatureWitness {
        fields: vec![r_point.x, r_point.y, z_fr],
    }
}

fn note_asset_id(note: &StatementV2Note) -> Fr254 {
    notev2::asset_id(
        note.asset_class_tag,
        note.token_contract,
        note.slot_id,
        note.predicate_root,
    )
}

fn note_commitment(note: &StatementV2Note) -> Fr254 {
    notev2::commitment_v2(
        note_asset_id(note),
        note.value,
        &note.pk_onetime,
        note.salt,
        note.mode_tag,
    )
}

fn base_note(value: u64, salt: u64, pk_onetime: Point) -> StatementV2Note {
    StatementV2Note {
        asset_class_tag: f(20),
        token_contract: f(0xabcd),
        slot_id: f(7),
        predicate_root: notev2::checksig_predicate_root(),
        value: f(value),
        pk_onetime,
        salt: f(salt),
        mode_tag: f(1),
    }
}

fn sender_onetime(ephemeral: u64) -> (Point, BjjFr) {
    let sender_root = f(31_337);
    let meta = notev2::meta_address_from_root_key(sender_root, f(9));
    let ephem = BjjFr::from(ephemeral);
    let pk = notev2::derive_onetime_address(&meta, ephem);
    let epk = notev2::ephemeral_public_key(ephem);
    let sk = notev2::recover_onetime_private(
        notev2::derive_spend_private_key(sender_root),
        notev2::derive_view_private_key(sender_root),
        &epk,
        meta.diversifier,
    );
    assert!(notev2::can_spend(sk, &pk), "one-time key mismatch");
    (pk, sk)
}

fn recipient_onetime(ephemeral: u64) -> Point {
    let meta = notev2::meta_address_from_root_key(f(42), f(17));
    notev2::derive_onetime_address(&meta, BjjFr::from(ephemeral))
}

fn reanchor_two_leaf_root(inp: &mut StatementV2Inputs) {
    let c0 = note_commitment(&inp.inputs[0].note);
    let c1 = note_commitment(&inp.inputs[1].note);
    inp.root = poseidon::hash(&[c0, c1]);
    inp.inputs[0].membership_proof = vec![merkle::PathElement {
        sibling: c1,
        sibling_on_left: false,
    }];
    inp.inputs[1].membership_proof = vec![merkle::PathElement {
        sibling: c0,
        sibling_on_left: true,
    }];
}

fn honest_inputs() -> StatementV2Inputs {
    let (pk0, sk0) = sender_onetime(1_001);
    let (pk1, sk1) = sender_onetime(1_002);
    let out_recipient = recipient_onetime(2_001);
    let (out_change, _) = sender_onetime(2_002);

    let script = canonical_ownership_script();
    let mut inp = StatementV2Inputs {
        root: Fr254::zero(),
        inputs: [
            StatementV2InputNote {
                note: base_note(700, 101, pk0),
                script,
                eval_witness: EvalWitness::default(),
                eval_ctx: EvalContext::default(),
                onetime_secret: sk0,
                membership_proof: Vec::new(),
            },
            StatementV2InputNote {
                note: base_note(300, 102, pk1),
                script,
                eval_witness: EvalWitness::default(),
                eval_ctx: EvalContext::default(),
                onetime_secret: sk1,
                membership_proof: Vec::new(),
            },
        ],
        outputs: [
            StatementV2OutputNote {
                note: base_note(600, 201, out_recipient),
            },
            StatementV2OutputNote {
                note: base_note(400, 202, out_change),
            },
        ],
    };
    reanchor_two_leaf_root(&mut inp);

    let input_commitments = [
        note_commitment(&inp.inputs[0].note),
        note_commitment(&inp.inputs[1].note),
    ];
    let messages = [
        vec![f(77), inp.root, f(0), input_commitments[0]],
        vec![f(77), inp.root, f(1), input_commitments[1]],
    ];
    let sig0 = sign(sk0, BjjFr::from(3_001u64), &messages[0]);
    let sig1 = sign(sk1, BjjFr::from(3_002u64), &messages[1]);

    inp.inputs[0].eval_witness = EvalWitness {
        signatures: vec![sig0],
        ..Default::default()
    };
    inp.inputs[0].eval_ctx = EvalContext {
        signature_hooks: vec![SignatureHook {
            public_key: pk0,
            message: messages[0].clone(),
        }],
        ..Default::default()
    };
    inp.inputs[1].eval_witness = EvalWitness {
        signatures: vec![sig1],
        ..Default::default()
    };
    inp.inputs[1].eval_ctx = EvalContext {
        signature_hooks: vec![SignatureHook {
            public_key: pk1,
            message: messages[1].clone(),
        }],
        ..Default::default()
    };
    inp
}

fn pad_message(message: &[Fr254]) -> String {
    assert!(message.len() <= MAX_MESSAGE_LEN);
    let mut words = vec![Fr254::zero(); MAX_MESSAGE_LEN];
    for (i, word) in message.iter().enumerate() {
        words[i] = *word;
    }
    arr_nr(&words)
}

fn arr_nr(xs: &[Fr254]) -> String {
    let items: Vec<String> = xs.iter().map(fdec).collect();
    format!("[{}]", items.join(", "))
}

fn sig_nr(sig: Option<&SignatureWitness>, hook: Option<&SignatureHook>) -> String {
    let fields = match (sig, hook) {
        (Some(sig), Some(hook)) => {
            assert_eq!(sig.fields.len(), 3, "Rust CHECKSIG witness layout drifted");
            let r_point = Point::new_unchecked(sig.fields[0], sig.fields[1]);
            let h = challenge_hash(checksig_domain(), &hook.public_key, &r_point, &hook.message);
            let (c_fr, lambda) = reduce_witness(h);
            vec![sig.fields[0], sig.fields[1], sig.fields[2], c_fr, lambda]
        }
        _ => vec![Fr254::zero(); 5],
    };
    format!("script::SignatureWitness {{ fields: {} }}", arr_nr(&fields))
}

fn multisig_nr() -> String {
    format!("script::MultisigWitness {{ fields: {} }}", arr_nr(&[Fr254::zero(); 8]))
}

fn neutral_point_nr() -> String {
    "Point { x: 0, y: 1 }".to_owned()
}

fn hook_nr(hook: Option<&SignatureHook>) -> String {
    match hook {
        Some(hook) => format!(
            "script::SignatureHook {{ public_key: {}, message: {}, message_len: {} }}",
            point_nr(&hook.public_key),
            pad_message(&hook.message),
            hook.message.len()
        ),
        None => format!(
            "script::SignatureHook {{ public_key: {}, message: {}, message_len: 0 }}",
            neutral_point_nr(),
            arr_nr(&[Fr254::zero(); MAX_MESSAGE_LEN])
        ),
    }
}

fn multisig_hook_nr() -> String {
    let pks = (0..4).map(|_| neutral_point_nr()).collect::<Vec<_>>().join(", ");
    format!(
        "script::MultisigHook {{ threshold: 0, public_keys: [{}], message: {}, message_len: 0 }}",
        pks,
        arr_nr(&[Fr254::zero(); MAX_MESSAGE_LEN])
    )
}

fn eval_witness_nr(w: &EvalWitness, ctx: &EvalContext) -> String {
    let sigs = (0..4)
        .map(|i| sig_nr(w.signatures.get(i), ctx.signature_hooks.get(i)))
        .collect::<Vec<_>>()
        .join(", ");
    let multisig = (0..4).map(|_| multisig_nr()).collect::<Vec<_>>().join(", ");
    format!(
        "script::EvalWitness {{ initial_stack: [0; script::STACK_DEPTH], initial_depth: 0, signatures: [{}], signature_count: {}, multisig: [{}], hash_preimages: [[0; 4]; script::MAX_HOOKS] }}",
        sigs,
        w.signatures.len(),
        multisig
    )
}

fn eval_ctx_nr(ctx: &EvalContext) -> String {
    let hooks = (0..4)
        .map(|i| hook_nr(ctx.signature_hooks.get(i)))
        .collect::<Vec<_>>()
        .join(", ");
    let multisig_hooks = (0..4).map(|_| multisig_hook_nr()).collect::<Vec<_>>().join(", ");
    format!(
        "script::EvalContext {{ clock: 0, sequence: 0, signature_hooks: [{}], signature_hook_count: {}, multisig_hooks: [{}], output_predicate_roots: [0; script::MAX_HOOKS], l1_state_roots: [0; script::MAX_HOOKS] }}",
        hooks,
        ctx.signature_hooks.len(),
        multisig_hooks
    )
}

fn path_nr(path: &[merkle::PathElement]) -> String {
    let elems = path
        .iter()
        .map(|e| {
            format!(
                "PathElement {{ sibling: {}, sibling_on_left: {} }}",
                fdec(&e.sibling), e.sibling_on_left
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", elems.join(", "))
}

fn note_nr(note: &StatementV2Note) -> String {
    format!(
        "StatementV2Note {{ asset_class_tag: {}, token_contract: {}, slot_id: {}, predicate_root: {}, value: {}, pk_onetime: {}, salt: {}, mode_tag: {} }}",
        fdec(&note.asset_class_tag),
        fdec(&note.token_contract),
        fdec(&note.slot_id),
        fdec(&note.predicate_root),
        fdec(&note.value),
        point_nr(&note.pk_onetime),
        fdec(&note.salt),
        fdec(&note.mode_tag),
    )
}

fn input_nr(input: &StatementV2InputNote) -> String {
    format!(
        "StatementV2InputNote {{ note: {}, script: ownership_script(), eval_witness: {}, eval_ctx: {}, onetime_secret: {}, membership_proof: {} }}",
        note_nr(&input.note),
        eval_witness_nr(&input.eval_witness, &input.eval_ctx),
        eval_ctx_nr(&input.eval_ctx),
        bdec(&input.onetime_secret),
        path_nr(&input.membership_proof),
    )
}

fn output_nr(output: &StatementV2OutputNote) -> String {
    format!("StatementV2OutputNote {{ note: {} }}", note_nr(&output.note))
}

fn emit_noir(manifest: &std::path::Path, inp: &StatementV2Inputs) {
    assert_eq!(inp.inputs.len(), N_IN);
    assert_eq!(inp.outputs.len(), N_OUT);
    let trace = compute_statement_v2(inp);
    let expected = trace.public_inputs.iter().map(fdec).collect::<Vec<_>>().join(", ");
    let body = format!(
        "//! AUTO-GENERATED by `rust/examples/gen_statement_v2.rs` — do not edit by hand.\n//!\n//! Frozen programmable-note v2 transfer parity vector produced from the Rust\n//! reference oracle.\n\nuse crate::bjj::Point;\nuse crate::merkle::PathElement;\nuse crate::script;\nuse crate::statement_v2::{{\n    StatementV2InputNote, StatementV2Inputs, StatementV2Note, StatementV2OutputNote,\n    NUM_PUBLIC_INPUTS_V2,\n}};\n\npub fn ownership_script() -> [script::OpCode; script::MAX_OPS] {{\n    let mut program: [script::OpCode; script::MAX_OPS] = [script::nop(); script::MAX_OPS];\n    program[0] = script::push(0);\n    program[1] = script::OpCode {{ tag: script::TAG_CHECKSIG, immediate: 0 }};\n    program\n}}\n\npub fn transfer() -> (StatementV2Inputs, [Field; NUM_PUBLIC_INPUTS_V2]) {{\n    let inp = StatementV2Inputs {{\n        root: {root},\n        inputs: [{in0}, {in1}],\n        outputs: [{out0}, {out1}],\n    }};\n    let expected: [Field; NUM_PUBLIC_INPUTS_V2] = [{expected}];\n    (inp, expected)\n}}\n",
        root = fdec(&inp.root),
        in0 = input_nr(&inp.inputs[0]),
        in1 = input_nr(&inp.inputs[1]),
        out0 = output_nr(&inp.outputs[0]),
        out1 = output_nr(&inp.outputs[1]),
        expected = expected,
    );
    let out = manifest.join("../noir/src/statement_v2_vectors.nr");
    std::fs::write(&out, body).expect("write statement_v2_vectors.nr");
    println!("wrote {}", out.display());
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let inp = honest_inputs();
    let trace = compute_statement_v2(&inp);
    println!(
        "statement_v2 public inputs = {:?}",
        trace.public_inputs.iter().map(fdec).collect::<Vec<_>>()
    );
    emit_noir(&manifest, &inp);
}
