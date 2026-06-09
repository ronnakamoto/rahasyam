//! Statement-v2 transfer oracle for programmable notes.
//!
//! This module is intentionally additive: it does not change the frozen v1
//! statement or its parity vectors.  It specifies the first end-to-end
//! programmable-note spend at the statement layer, restricted to a clean
//! transfer shape with two spent notes and two output notes.  `N_IN = 2` and
//! `N_OUT = 2` are deliberate: one recipient note plus one sender-change note is
//! the smallest shape that exercises multi-input membership, per-asset balance,
//! duplicate checks, output reconstruction, predicate execution, and the
//! owner-binding constraint without dragging in the orthogonal deposit,
//! withdraw, or swap modes.
//!
//! ## Threat model and soundness contract
//!
//! The adversary controls every private witness field: note preimages,
//! predicate scripts, predicate witnesses, evaluation contexts, Merkle paths, and
//! output fields.  The public statement is only the framed vector returned in
//! [`StatementV2Trace::public_inputs`].  The oracle therefore fails closed with
//! explicit assertions for every constraint the UltraHonk circuit must mirror.
//!
//! The key soundness point is owner binding.  A v2 asset id commits the predicate
//! *program* through `predicate_root`, but not the runtime key used by
//! `CHECKSIG`.  Without a statement constraint equating each spend-authorizing
//! signature hook key to the note's committed `pk_onetime`, an attacker could
//! keep the victim's note commitment and substitute their own key in the
//! predicate context.  This module treats every `CHECKSIG` signature hook in an
//! input predicate as spend-authorizing and requires its public key coordinates
//! to equal that input note's committed one-time key.
//!
//! Nullifiers are bound to the note's one-time **secret** key, not to a free
//! `root_key` witness.  In v1, `nullifier_key = nullifier_key(root_key)` is sound
//! only because the v1 ownership check (`zkp_pub_key(root_key) == committed key`)
//! forces a unique `root_key`, hence a unique nullifier.  A v2 note instead
//! commits a stealth `pk_onetime`, so re-using the v1 spend-key branch with an
//! unconstrained `root_key` would make the nullifier malleable: the legitimate
//! owner could derive a different nullifier for the same committed note and
//! double-spend.  This module closes that gap Sapling-style — each input carries
//! its one-time secret `sk_onetime`, the statement enforces
//! `sk_onetime·G == pk_onetime` (so the secret is the unique discrete log of the
//! committed key), and the nullifier is
//! `Poseidon(nullifier_key(sk_onetime), commitment)`.  This makes the nullifier a
//! deterministic, hiding function of the note that only the owner can produce and
//! that the note's sender cannot link.  The deposit/neutral-secret branch is
//! intentionally out of scope for this transfer-only v2 slice.

use crate::predvm::{self, EvalContext, EvalWitness, OpCode, MAX_OPS};
use crate::{bjj, keys, merkle, notev2, poseidon, BjjFr, Fr254, Point};
use ark_ff::{BigInteger, PrimeField, Zero};

/// Number of spent notes in the transfer-v2 statement.
pub const N_IN: usize = 2;
/// Number of created notes in the transfer-v2 statement.
pub const N_OUT: usize = 2;

/// Public-input framing for this fixed transfer-v2 statement shape.
///
/// The public-input vector is fixed-width and therefore does not need internal
/// length fields: `[domain, root, nf_0, nf_1, out_0, out_1]`.  The domain word
/// separates this v2 transfer frame from the v1 `public_inputsversion2` vector
/// and from future v2 shapes with different arities or modes.
pub fn public_inputs_framing_v2() -> Fr254 {
    Fr254::from_le_bytes_mod_order(b"NF4_STATEMENT_V2_TRANSFER")
}

/// Canonical ownership predicate: `[Push(0), CheckSig]` padded with `Nop`.
///
/// Its root is [`notev2::checksig_predicate_root`].  The script is
/// owner-independent by design; the owner is bound by the statement-level check
/// tying signature hooks to [`StatementV2Note::pk_onetime`].
pub fn canonical_ownership_script() -> [OpCode; MAX_OPS] {
    let mut script = [OpCode::Nop; MAX_OPS];
    script[0] = OpCode::Push(Fr254::zero());
    script[1] = OpCode::CheckSig;
    script
}

/// Reconstructable v2 note preimage shared by input and output notes.
#[derive(Clone, Debug)]
pub struct StatementV2Note {
    /// Asset class / standard tag.  Interpreted by the predicate, not by the
    /// hot commitment path.
    pub asset_class_tag: Fr254,
    /// Token contract or asset namespace.
    pub token_contract: Fr254,
    /// Slot / token id inside the asset namespace.
    pub slot_id: Fr254,
    /// Committed predicate-program root for this asset identity.
    pub predicate_root: Fr254,
    /// 96-bit note value.
    pub value: Fr254,
    /// Per-note stealth owner key committed into `commitment_v2`.
    pub pk_onetime: Point,
    /// Commitment blinding salt.
    pub salt: Fr254,
    /// Mode tag; this module uses transfer mode in tests but keeps the field
    /// explicit so the Noir mirror sees the same arity-6 commitment preimage.
    pub mode_tag: Fr254,
}

/// Private witness for one spent v2 note.
#[derive(Clone, Debug)]
pub struct StatementV2InputNote {
    /// Reconstructable spent-note fields.
    pub note: StatementV2Note,
    /// Fixed-size predicate program committed by `note.predicate_root`.
    pub script: [OpCode; MAX_OPS],
    /// Private predicate witness consumed by the bounded predicate VM.
    pub eval_witness: EvalWitness,
    /// Statement-bound predicate context.  All `CHECKSIG` hook public keys are
    /// constrained to equal `note.pk_onetime`.
    pub eval_ctx: EvalContext,
    /// One-time spend secret for this note.  The statement enforces
    /// `sk_onetime·G == note.pk_onetime`, pinning it to the unique discrete log
    /// of the committed key so the derived nullifier cannot be made malleable.
    pub onetime_secret: BjjFr,
    /// Binary Poseidon Merkle path proving the reconstructed commitment is under
    /// [`StatementV2Inputs::root`].
    pub membership_proof: Vec<merkle::PathElement>,
}

/// Private witness for one created v2 note.
#[derive(Clone, Debug)]
pub struct StatementV2OutputNote {
    /// Reconstructable output-note fields.
    pub note: StatementV2Note,
}

/// Full witness for the fixed 2-in/2-out programmable-note transfer statement.
#[derive(Clone, Debug)]
pub struct StatementV2Inputs {
    /// Public commitment-tree root for all spent notes.
    pub root: Fr254,
    /// Spent note witnesses.
    pub inputs: [StatementV2InputNote; N_IN],
    /// Created note witnesses: conventionally `[recipient, change]`.
    pub outputs: [StatementV2OutputNote; N_OUT],
}

/// Output trace of the statement-v2 oracle.
#[derive(Clone, Debug)]
pub struct StatementV2Trace {
    /// Reconstructed spent-note commitments.
    pub input_commitments: [Fr254; N_IN],
    /// Spend-key nullifiers `Poseidon(nullifier_key(root_key), commitment_i)`.
    pub nullifiers: [Fr254; N_IN],
    /// Reconstructed output commitments.
    pub output_commitments: [Fr254; N_OUT],
    /// Framed public-input vector: `[domain, root, nf_0, nf_1, out_0, out_1]`.
    pub public_inputs: Vec<Fr254>,
}

fn assert_max_bits(v: Fr254, bits: u32, name: &str) {
    let limit = num_bigint::BigUint::from(1u8) << bits;
    let val = num_bigint::BigUint::from_bytes_be(&v.into_bigint().to_bytes_be());
    assert!(val < limit, "{name} exceeds {bits} bits");
}

fn point_coords_equal(a: &Point, b: &Point) -> bool {
    a.x == b.x && a.y == b.y
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

fn script_uses_checksig(script: &[OpCode; MAX_OPS]) -> bool {
    script.iter().any(|op| matches!(op, OpCode::CheckSig))
}

fn assert_owner_binding(i: usize, input: &StatementV2InputNote) {
    if !script_uses_checksig(&input.script) {
        return;
    }

    if input.script == canonical_ownership_script() {
        assert_eq!(
            input.eval_ctx.signature_hooks.len(),
            1,
            "statement_v2 input {i}: canonical ownership hook count mismatch"
        );
    }

    for hook in &input.eval_ctx.signature_hooks {
        assert!(
            point_coords_equal(&hook.public_key, &input.note.pk_onetime),
            "statement_v2 input {i}: owner-binding violation"
        );
    }
}

fn assert_predicate(i: usize, input: &StatementV2InputNote) {
    let computed_root = predvm::predicate_root(&input.script);
    assert_eq!(
        input.note.predicate_root, computed_root,
        "statement_v2 input {i}: predicate root mismatch"
    );

    assert_owner_binding(i, input);

    match predvm::evaluate(&input.script, &input.eval_witness, &input.eval_ctx) {
        Ok(true) => {}
        Ok(false) | Err(_) => panic!("statement_v2 input {i}: predicate evaluation failed"),
    }
}

/// Bind the spend secret to the committed one-time key and return the per-input
/// nullifier key.
///
/// Enforcing `sk_onetime·G == pk_onetime` pins `sk_onetime` to the unique
/// discrete log of the note's committed key, so the resulting nullifier is a
/// deterministic function of the note alone — it cannot be made malleable by a
/// free witness, which would otherwise enable a double-spend.
fn input_nullifier_key(i: usize, input: &StatementV2InputNote) -> Fr254 {
    assert!(
        !input.onetime_secret.is_zero(),
        "statement_v2 input {i}: one-time secret is zero"
    );
    assert!(
        bjj::mul_by_generator(input.onetime_secret) == input.note.pk_onetime,
        "statement_v2 input {i}: one-time key binding violation"
    );
    let secret_fr =
        Fr254::from_le_bytes_mod_order(&input.onetime_secret.into_bigint().to_bytes_le());
    keys::nullifier_key(secret_fr)
}

fn assert_membership(i: usize, root: Fr254, commitment: Fr254, path: &[merkle::PathElement]) {
    let computed_root = merkle::compute_root(commitment, path);
    assert_eq!(
        computed_root, root,
        "statement_v2 input {i}: membership proof failed"
    );
}

fn assert_no_duplicate_nonzero<const N: usize>(values: &[Fr254; N], label: &str) {
    for i in 0..N {
        for j in (i + 1)..N {
            assert!(
                values[j].is_zero() || values[j] != values[i],
                "statement_v2: duplicate {label}"
            );
        }
    }
}

fn assert_value_conservation(
    input_assets: &[Fr254; N_IN],
    input_values: &[Fr254; N_IN],
    output_assets: &[Fr254; N_OUT],
    output_values: &[Fr254; N_OUT],
) {
    for asset in input_assets.iter().chain(output_assets.iter()) {
        let in_sum = input_assets
            .iter()
            .zip(input_values.iter())
            .filter(|(candidate, _)| *candidate == asset)
            .fold(Fr254::zero(), |acc, (_, value)| acc + value);
        let out_sum = output_assets
            .iter()
            .zip(output_values.iter())
            .filter(|(candidate, _)| *candidate == asset)
            .fold(Fr254::zero(), |acc, (_, value)| acc + value);
        assert_eq!(in_sum, out_sum, "statement_v2: value conservation failed");
    }
}

/// Compute and enforce the fixed transfer-v2 statement.
///
/// The function reconstructs all note commitments from witness fields, proves
/// input membership under the public root, evaluates and binds each predicate,
/// derives v1-compatible spend-key nullifiers, checks duplicate public outputs,
/// enforces per-asset value conservation, and returns the exact public input
/// frame the circuit must expose.
pub fn compute_statement_v2(inp: &StatementV2Inputs) -> StatementV2Trace {
    for (i, input) in inp.inputs.iter().enumerate() {
        assert_max_bits(input.note.value, 96, "statement_v2 input value");
        assert_predicate(i, input);
    }
    for output in &inp.outputs {
        assert_max_bits(output.note.value, 96, "statement_v2 output value");
    }

    let input_asset_ids: [Fr254; N_IN] =
        std::array::from_fn(|i| note_asset_id(&inp.inputs[i].note));
    let input_values: [Fr254; N_IN] = std::array::from_fn(|i| inp.inputs[i].note.value);
    let output_asset_ids: [Fr254; N_OUT] =
        std::array::from_fn(|i| note_asset_id(&inp.outputs[i].note));
    let output_values: [Fr254; N_OUT] = std::array::from_fn(|i| inp.outputs[i].note.value);

    let input_commitments: [Fr254; N_IN] =
        std::array::from_fn(|i| note_commitment(&inp.inputs[i].note));
    for (i, input) in inp.inputs.iter().enumerate() {
        assert_membership(i, inp.root, input_commitments[i], &input.membership_proof);
    }

    assert_value_conservation(
        &input_asset_ids,
        &input_values,
        &output_asset_ids,
        &output_values,
    );

    let nullifiers: [Fr254; N_IN] = std::array::from_fn(|i| {
        let nf_key = input_nullifier_key(i, &inp.inputs[i]);
        poseidon::hash(&[nf_key, input_commitments[i]])
    });
    let output_commitments: [Fr254; N_OUT] =
        std::array::from_fn(|i| note_commitment(&inp.outputs[i].note));

    assert_no_duplicate_nonzero(&nullifiers, "nullifier");
    assert_no_duplicate_nonzero(&output_commitments, "commitment");

    let mut public_inputs = Vec::with_capacity(2 + N_IN + N_OUT);
    public_inputs.push(public_inputs_framing_v2());
    public_inputs.push(inp.root);
    public_inputs.extend_from_slice(&nullifiers);
    public_inputs.extend_from_slice(&output_commitments);

    StatementV2Trace {
        input_commitments,
        nullifiers,
        output_commitments,
        public_inputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predvm::{SignatureHook, SignatureWitness};
    use crate::{bjj, fr_to_dec};
    use nf_curves::ed_on_bn254::Fr as BjjFr;

    fn f(v: u64) -> Fr254 {
        Fr254::from(v)
    }

    fn checksig_domain() -> Fr254 {
        Fr254::from_le_bytes_mod_order(b"PREDVM_CHECKSIG_V1")
    }

    fn reduce_to_bjj(c_fr: Fr254) -> BjjFr {
        BjjFr::from_be_bytes_mod_order(&c_fr.into_bigint().to_bytes_be())
    }

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

    fn sign(s: BjjFr, r: BjjFr, message: &[Fr254]) -> SignatureWitness {
        let pk = bjj::mul_by_generator(s);
        let r_point = bjj::mul_by_generator(r);
        let c = challenge(checksig_domain(), &pk, &r_point, message);
        let z = r + c * s;
        let z_fr = Fr254::from_le_bytes_mod_order(&z.into_bigint().to_bytes_le());
        SignatureWitness {
            fields: vec![r_point.x, r_point.y, z_fr],
        }
    }

    fn dec_array<const N: usize>(xs: &[Fr254; N]) -> Vec<String> {
        xs.iter().map(fr_to_dec).collect()
    }

    fn dec_vec(xs: &[Fr254]) -> Vec<String> {
        xs.iter().map(fr_to_dec).collect()
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
        assert!(
            notev2::can_spend(sk, &pk),
            "test setup: one-time key mismatch"
        );
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

    #[test]
    fn honest_transfer_v2_matches_frozen_vectors() {
        let inp = honest_inputs();
        let trace = compute_statement_v2(&inp);
        assert_eq!(
            dec_array(&trace.nullifiers),
            vec![
                "11736254725105509315070677083918395796306567665389899743777423512141380927517",
                "6571100980962241999777255198951328968511830722875413911279944576082032457012",
            ],
            "statement_v2 nullifier vector drifted"
        );
        assert_eq!(
            dec_array(&trace.output_commitments),
            vec![
                "3410674823084329493958826537896693858781287422787097696627947765219681494034",
                "20937480563211378528776349484986771575635033355038060798717971570191391197047",
            ],
            "statement_v2 output commitment vector drifted"
        );
        assert_eq!(
            dec_vec(&trace.public_inputs),
            vec![
                "516420953215171890327788881277379126594098488104739946120782",
                "20949402313405868079925305360944511049519988039112861149764691839753676908184",
                "11736254725105509315070677083918395796306567665389899743777423512141380927517",
                "6571100980962241999777255198951328968511830722875413911279944576082032457012",
                "3410674823084329493958826537896693858781287422787097696627947765219681494034",
                "20937480563211378528776349484986771575635033355038060798717971570191391197047",
            ],
            "statement_v2 public-input vector drifted"
        );
    }

    #[test]
    #[should_panic(expected = "statement_v2 input 1: one-time key binding violation")]
    fn unbound_nullifier_secret_fails_closed() {
        // The nullifier must be bound to the note's committed one-time key.  A
        // secret that does not satisfy `sk·G == pk_onetime` would let the owner
        // mint a second, distinct nullifier for the same committed note and
        // double-spend; the statement must reject it.
        let mut inp = honest_inputs();
        inp.inputs[1].onetime_secret += BjjFr::from(1u64);
        compute_statement_v2(&inp);
    }

    #[test]
    fn nullifier_is_pinned_to_the_committed_one_time_key() {
        // There is exactly one secret accepted per input (the discrete log of the
        // committed key), so the nullifier is a deterministic function of the
        // note and cannot be made malleable.
        let inp = honest_inputs();
        let trace = compute_statement_v2(&inp);
        for i in 0..N_IN {
            assert_eq!(
                bjj::mul_by_generator(inp.inputs[i].onetime_secret),
                inp.inputs[i].note.pk_onetime,
                "test setup: input {i} secret must open the committed key"
            );
            let secret_fr = Fr254::from_le_bytes_mod_order(
                &inp.inputs[i].onetime_secret.into_bigint().to_bytes_le(),
            );
            let expected =
                poseidon::hash(&[keys::nullifier_key(secret_fr), trace.input_commitments[i]]);
            assert_eq!(trace.nullifiers[i], expected, "nullifier {i} not key-bound");
        }
    }

    #[test]
    #[should_panic(expected = "statement_v2 input 0: owner-binding violation")]
    fn wrong_owner_key_in_checksig_hook_fails_closed() {
        let mut inp = honest_inputs();
        let wrong_sk = BjjFr::from(9_999u64);
        let wrong_pk = bjj::mul_by_generator(wrong_sk);
        let message = inp.inputs[0].eval_ctx.signature_hooks[0].message.clone();
        inp.inputs[0].eval_ctx.signature_hooks[0].public_key = wrong_pk;
        inp.inputs[0].eval_witness.signatures[0] = sign(wrong_sk, BjjFr::from(8_888u64), &message);
        compute_statement_v2(&inp);
    }

    #[test]
    #[should_panic(expected = "statement_v2 input 0: predicate evaluation failed")]
    fn bad_signature_predicate_false_fails_closed() {
        let mut inp = honest_inputs();
        inp.inputs[0].eval_witness.signatures[0].fields[2] += f(1);
        compute_statement_v2(&inp);
    }

    #[test]
    #[should_panic(expected = "statement_v2 input 0: predicate root mismatch")]
    fn predicate_root_mismatch_fails_closed() {
        let mut inp = honest_inputs();
        inp.inputs[0].note.predicate_root = f(1_234_567);
        reanchor_two_leaf_root(&mut inp);
        compute_statement_v2(&inp);
    }

    #[test]
    #[should_panic(expected = "statement_v2: value conservation failed")]
    fn value_imbalance_fails_closed() {
        let mut inp = honest_inputs();
        inp.outputs[0].note.value += f(1);
        compute_statement_v2(&inp);
    }

    #[test]
    #[should_panic(expected = "statement_v2 input 0: membership proof failed")]
    fn tampered_membership_proof_fails_closed() {
        let mut inp = honest_inputs();
        inp.inputs[0].membership_proof[0].sibling += f(1);
        compute_statement_v2(&inp);
    }

    #[test]
    #[should_panic(expected = "exceeds 96 bits")]
    fn over_96_bit_value_fails_closed() {
        let mut inp = honest_inputs();
        inp.inputs[0].note.value = Fr254::from(num_bigint::BigUint::from(1u8) << 96u32);
        compute_statement_v2(&inp);
    }

    #[test]
    fn honest_checksig_uses_the_predvm_fiat_shamir_transcript() {
        let sk = BjjFr::from(12_345u64);
        let pk = bjj::mul_by_generator(sk);
        let message = vec![f(1), f(2), f(3)];
        let sig = sign(sk, BjjFr::from(67_890u64), &message);
        let witness = EvalWitness {
            signatures: vec![sig],
            ..Default::default()
        };
        let ctx = EvalContext {
            signature_hooks: vec![SignatureHook {
                public_key: pk,
                message,
            }],
            ..Default::default()
        };
        assert_eq!(
            predvm::evaluate(&canonical_ownership_script(), &witness, &ctx),
            Ok(true),
            "test signer must match predvm::auth challenge framing"
        );
        assert_eq!(pk, bjj::mul_by_generator(sk));
    }
}
