#![cfg(all(test, feature = "ultra-honk-v1"))]

use alloy::primitives::Address;
use ark_bn254::Fr as Fr254;
use ark_ec::twisted_edwards::Affine as TEAffine;
use jf_primitives::trees::{Directions, MembershipProof, PathElement};
use nf_curves::ed_on_bn254::BabyJubjub;
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::env;

use super::{witness, UltraHonkClientEngine, UltraHonkProof};
use crate::nf_client_proof::{PrivateInputs, ProvingEngine, PublicInputs};
use crate::shared_entities::DepositData;

fn transfer_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/transfer.json")).expect("valid transfer fixture")
}

fn parse_biguint(value: &Value) -> BigUint {
    let raw = value
        .as_str()
        .expect("field element must be a string")
        .trim();
    let (digits, radix) = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map(|s| (s, 16))
        .unwrap_or((raw, 10));
    BigUint::parse_bytes(digits.as_bytes(), radix).expect("valid integer string")
}

fn parse_fr(value: &Value) -> Fr254 {
    Fr254::from(parse_biguint(value))
}

fn parse_field(inputs: &Value, name: &str) -> Fr254 {
    parse_fr(&inputs[name])
}

fn parse_address(value: &Value) -> Address {
    let bytes = parse_biguint(value).to_bytes_be();
    assert!(bytes.len() <= 20, "address field exceeds 20 bytes");
    let mut padded = [0u8; 20];
    padded[20 - bytes.len()..].copy_from_slice(&bytes);
    Address::from(padded)
}

fn parse_fr_array<const N: usize>(value: &Value) -> [Fr254; N] {
    let values = value.as_array().expect("field must be an array");
    assert_eq!(values.len(), N);
    std::array::from_fn(|i| parse_fr(&values[i]))
}

fn parse_point(value: &Value) -> TEAffine<BabyJubjub> {
    TEAffine::<BabyJubjub>::new(parse_fr(&value["x"]), parse_fr(&value["y"]))
}

fn parse_points<const N: usize>(value: &Value) -> [TEAffine<BabyJubjub>; N] {
    let values = value.as_array().expect("points must be an array");
    assert_eq!(values.len(), N);
    std::array::from_fn(|i| parse_point(&values[i]))
}

fn parse_secret_preimages(value: &Value) -> [[Fr254; 3]; 4] {
    let rows = value.as_array().expect("secret preimages must be an array");
    assert_eq!(rows.len(), 4);
    std::array::from_fn(|i| parse_fr_array::<3>(&rows[i]))
}

fn parse_deposits(inputs: &Value) -> [DepositData; 4] {
    let token_ids = parse_fr_array::<4>(&inputs["deposit_token_ids"]);
    let slot_ids = parse_fr_array::<4>(&inputs["deposit_slot_ids"]);
    let values = parse_fr_array::<4>(&inputs["deposit_values"]);
    let secret_hashes = parse_fr_array::<4>(&inputs["deposit_secret_hashes"]);

    std::array::from_fn(|i| DepositData {
        nf_token_id: token_ids[i],
        nf_slot_id: slot_ids[i],
        value: values[i],
        secret_hash: secret_hashes[i],
    })
}

fn parse_membership_proofs(inputs: &Value) -> [MembershipProof<Fr254>; 4] {
    let proofs = inputs["membership_proofs"]
        .as_array()
        .expect("membership proofs must be an array");
    assert_eq!(proofs.len(), 4);
    let nullifier_values = parse_fr_array::<4>(&inputs["nullifiers_values"]);

    std::array::from_fn(|i| {
        let path = proofs[i]
            .as_array()
            .expect("membership path must be an array");
        assert_eq!(path.len(), 32);
        let sibling_path = path
            .iter()
            .map(|entry| PathElement {
                direction: if entry["sibling_on_left"]
                    .as_bool()
                    .expect("sibling_on_left must be a bool")
                {
                    Directions::HashWithThisNodeOnLeft
                } else {
                    Directions::HashWithThisNodeOnRight
                },
                value: parse_fr(&entry["sibling"]),
            })
            .collect::<Vec<_>>();
        MembershipProof {
            node_value: nullifier_values[i],
            sibling_path,
            leaf_index: 0,
        }
    })
}

fn build_private_inputs(inputs: &Value) -> PrivateInputs {
    PrivateInputs {
        fee_token_id: parse_field(inputs, "fee_token_id"),
        nf_address: parse_address(&inputs["nf_address"]),
        nf_slot_id: parse_field(inputs, "nf_slot_id"),
        nullifiers_values: parse_fr_array::<4>(&inputs["nullifiers_values"]),
        nullifiers_salts: parse_fr_array::<4>(&inputs["nullifiers_salts"]),
        membership_proofs: parse_membership_proofs(inputs),
        commitments_values: parse_fr_array::<2>(&inputs["commitments_values"]),
        sender_commitment_salts: parse_fr_array::<3>(&inputs["sender_commitment_salts"]),
        public_keys: parse_points::<4>(&inputs["public_keys"]),
        root_key: parse_field(inputs, "root_key"),
        ephemeral_key: parse_field(inputs, "ephemeral_key"),
        withdraw_address: parse_field(inputs, "withdraw_address"),
        secret_preimages: parse_secret_preimages(&inputs["secret_preimages"]),
        deposit_data: parse_deposits(inputs),
        party_a_public_key: parse_point(&inputs["party_a_public_key"]),
        party_b_public_key: parse_point(&inputs["party_b_public_key"]),
        nf_token_a_id: parse_field(inputs, "nf_token_a_id"),
        value_a: parse_field(inputs, "value_a"),
        nf_token_b_id: parse_field(inputs, "nf_token_b_id"),
        value_b: parse_field(inputs, "value_b"),
        swap_nonce: parse_field(inputs, "swap_nonce"),
        deadline: parse_field(inputs, "deadline"),
    }
}

fn build_public_inputs(inputs: &Value, outputs: &Value) -> PublicInputs {
    PublicInputs {
        fee: parse_field(inputs, "fee"),
        root: parse_field(inputs, "root"),
        commitments: parse_fr_array::<4>(&outputs["commitments"]),
        nullifiers: parse_fr_array::<4>(&outputs["nullifiers"]),
        compressed_secrets: parse_fr_array::<5>(&outputs["compressed_secrets"]),
        swap_link: parse_fr(&outputs["swap_link"]),
        deadline: parse_fr(&outputs["final_deadline"]),
        swap_side: parse_fr(&outputs["swap_side"]),
    }
}

fn build_transfer_inputs() -> (PrivateInputs, PublicInputs, Value) {
    let fixture = transfer_fixture();
    assert_eq!(fixture["name"], "transfer");
    let inputs = &fixture["inputs"];
    let outputs = &fixture["outputs"];
    let public_inputs = build_public_inputs(inputs, outputs);
    let expected_public_inputs = parse_fr_array::<27>(&outputs["public_inputs"]).to_vec();
    assert_eq!(Vec::<Fr254>::from(&public_inputs), expected_public_inputs);
    (build_private_inputs(inputs), public_inputs, fixture)
}

fn rename_membership_proofs(value: &Value) -> Value {
    Value::Array(
        value
            .as_array()
            .expect("membership proofs must be an array")
            .iter()
            .map(|path| {
                Value::Array(
                    path.as_array()
                        .expect("membership path must be an array")
                        .iter()
                        .map(|entry| {
                            json!({
                                "sibling": entry["sibling"].clone(),
                                "siblingOnLeft": entry["sibling_on_left"].clone(),
                            })
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

fn expected_statement_json(fixture: &Value) -> Value {
    let inputs = &fixture["inputs"];
    let outputs = &fixture["outputs"];
    json!({
        "root": inputs["root"].clone(),
        "rootKey": inputs["root_key"].clone(),
        "zkpPriv": outputs["zkp_priv"].clone(),
        "zkpPrivLambda": outputs["zkp_priv_lambda"].clone(),
        "ephemeralKey": inputs["ephemeral_key"].clone(),
        "feeTokenId": inputs["fee_token_id"].clone(),
        "fee": inputs["fee"].clone(),
        "nfAddress": inputs["nf_address"].clone(),
        "nfSlotId": inputs["nf_slot_id"].clone(),
        "nullifiersValues": inputs["nullifiers_values"].clone(),
        "nullifiersSalts": inputs["nullifiers_salts"].clone(),
        "publicKeys": inputs["public_keys"].clone(),
        "membershipProofs": rename_membership_proofs(&inputs["membership_proofs"]),
        "secretPreimages": inputs["secret_preimages"].clone(),
        "commitmentsValues": inputs["commitments_values"].clone(),
        "senderCommitmentSalts": inputs["sender_commitment_salts"].clone(),
        "depositTokenIds": inputs["deposit_token_ids"].clone(),
        "depositSlotIds": inputs["deposit_slot_ids"].clone(),
        "depositValues": inputs["deposit_values"].clone(),
        "depositSecretHashes": inputs["deposit_secret_hashes"].clone(),
        "withdrawAddress": inputs["withdraw_address"].clone(),
        "partyAPublicKey": inputs["party_a_public_key"].clone(),
        "partyBPublicKey": inputs["party_b_public_key"].clone(),
        "nfTokenAId": inputs["nf_token_a_id"].clone(),
        "valueA": inputs["value_a"].clone(),
        "nfTokenBId": inputs["nf_token_b_id"].clone(),
        "valueB": inputs["value_b"].clone(),
        "swapNonce": inputs["swap_nonce"].clone(),
        "deadline": inputs["deadline"].clone(),
    })
}

fn decimal_string(value: &Value) -> Option<String> {
    value.as_str().and_then(|s| {
        let raw = s.trim();
        let (digits, radix) = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .map(|digits| (digits, 16))
            .unwrap_or((raw, 10));
        BigUint::parse_bytes(digits.as_bytes(), radix).map(|n| n.to_str_radix(10))
    })
}

fn canonicalize_numbers(value: &Value) -> Value {
    match value {
        Value::String(_) => decimal_string(value)
            .map(Value::String)
            .unwrap_or_else(|| value.clone()),
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_numbers).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_numbers(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn assert_statement_matches_frozen(actual: &Value, expected: &Value) {
    let actual = canonicalize_numbers(actual);
    let expected = canonicalize_numbers(expected);
    assert_eq!(actual, expected);
}

#[test]
fn ultrahonk_v1_transfer_witness_mapping_matches_frozen_vector() {
    let (private_inputs, public_inputs, fixture) = build_transfer_inputs();
    let actual = witness::build_statement_inputs_json(&private_inputs, &public_inputs).unwrap();
    let expected = expected_statement_json(&fixture);

    assert_statement_matches_frozen(&actual, &expected);
    assert_eq!(actual["membershipProofs"][0].as_array().unwrap().len(), 32);
    assert_eq!(actual["zkpPriv"], fixture["outputs"]["zkp_priv"]);
    assert_eq!(
        actual["zkpPrivLambda"],
        fixture["outputs"]["zkp_priv_lambda"]
    );
}

#[test]
#[ignore = "runs the Node UltraHonk sidecar and takes roughly 40s per proof"]
fn ultrahonk_v1_live_sidecar_prove_verify_transfer_vector() {
    let (mut private_inputs, full_public_inputs, _fixture) = build_transfer_inputs();
    let sidecar_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lib crate must be inside workspace")
        .join("ultrahonk_sidecar");
    env::set_var("ULTRAHONK_SIDECAR_DIR", sidecar_dir);

    // Mimic the production client (`client_operation.rs`): the caller only sets
    // `fee` and `root`; `prove` must populate commitments / nullifiers /
    // compressed_secrets / swap fields from the circuit output via the
    // `&mut public_inputs` out-parameter contract.
    let mut public_inputs = PublicInputs::new();
    public_inputs.fee = full_public_inputs.fee;
    public_inputs.root = full_public_inputs.root;

    let proof = UltraHonkClientEngine::prove(&mut private_inputs, &mut public_inputs)
        .expect("sidecar should prove the frozen transfer vector");

    // The out-parameter must now equal the fully-populated reference vector.
    assert_eq!(public_inputs.commitments, full_public_inputs.commitments);
    assert_eq!(public_inputs.nullifiers, full_public_inputs.nullifiers);
    assert_eq!(
        public_inputs.compressed_secrets,
        full_public_inputs.compressed_secrets
    );
    assert_eq!(public_inputs.swap_link, full_public_inputs.swap_link);
    assert_eq!(public_inputs.deadline, full_public_inputs.deadline);
    assert_eq!(public_inputs.swap_side, full_public_inputs.swap_side);

    assert!(UltraHonkClientEngine::verify(&proof, &public_inputs)
        .expect("sidecar should verify the frozen transfer proof"));

    let mut tampered = UltraHonkProof {
        proof: proof.proof.clone(),
        public_inputs: proof.public_inputs.clone(),
    };
    assert!(!tampered.proof.is_empty());
    tampered.proof[0] ^= 0x01;
    assert!(!UltraHonkClientEngine::verify(&tampered, &public_inputs)
        .expect("tampered proof should be rejected, not crash"));
}
