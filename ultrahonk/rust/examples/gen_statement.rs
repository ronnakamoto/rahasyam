//! Generate the full-statement parity vectors (transfer / withdraw / swap) and
//! the matching Noir test fixtures + circuit `Prover.toml`, from the real
//! Nightfish primitives.
//!
//! ```sh
//! cargo run --example gen_statement
//! ```

use std::path::PathBuf;

use ark_bn254::Fr as Fr254;
use nightfish_honk_ref::{
    fr_to_dec, keys, merkle::PathElement, statement::compute_statement, statement::scenarios,
    statement::StatementInputs, Point,
};

fn point_json(p: &Point) -> serde_json::Value {
    serde_json::json!({ "x": fr_to_dec(&p.x), "y": fr_to_dec(&p.y) })
}

fn path_json(path: &[PathElement]) -> serde_json::Value {
    serde_json::Value::Array(
        path.iter()
            .map(|e| {
                serde_json::json!({
                    "sibling": fr_to_dec(&e.sibling),
                    "sibling_on_left": e.sibling_on_left,
                })
            })
            .collect(),
    )
}

fn inputs_json(inp: &StatementInputs) -> serde_json::Value {
    serde_json::json!({
        "root": fr_to_dec(&inp.root),
        "root_key": fr_to_dec(&inp.root_key),
        "ephemeral_key": nightfish_honk_ref::bjj_to_dec(&inp.ephemeral_key),
        "fee_token_id": fr_to_dec(&inp.fee_token_id),
        "fee": fr_to_dec(&inp.fee),
        "nf_address": fr_to_dec(&inp.nf_address),
        "nf_slot_id": fr_to_dec(&inp.nf_slot_id),
        "nullifiers_values": inp.nullifiers_values.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "nullifiers_salts": inp.nullifiers_salts.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "public_keys": inp.public_keys.iter().map(point_json).collect::<Vec<_>>(),
        "membership_proofs": inp.membership_proofs.iter().map(|p| path_json(p)).collect::<Vec<_>>(),
        "secret_preimages": inp.secret_preimages.iter()
            .map(|sp| sp.iter().map(fr_to_dec).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "commitments_values": inp.commitments_values.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "sender_commitment_salts": inp.sender_commitment_salts.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "deposit_token_ids": inp.deposit_token_ids.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "deposit_slot_ids": inp.deposit_slot_ids.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "deposit_values": inp.deposit_values.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "deposit_secret_hashes": inp.deposit_secret_hashes.iter().map(fr_to_dec).collect::<Vec<_>>(),
        "withdraw_address": fr_to_dec(&inp.withdraw_address),
        "party_a_public_key": point_json(&inp.party_a_public_key),
        "party_b_public_key": point_json(&inp.party_b_public_key),
        "nf_token_a_id": fr_to_dec(&inp.nf_token_a_id),
        "value_a": fr_to_dec(&inp.value_a),
        "nf_token_b_id": fr_to_dec(&inp.nf_token_b_id),
        "value_b": fr_to_dec(&inp.value_b),
        "swap_nonce": fr_to_dec(&inp.swap_nonce),
        "deadline": fr_to_dec(&inp.deadline),
    })
}

fn scenario_json(name: &str, inp: &StatementInputs) -> serde_json::Value {
    let t = compute_statement(inp);
    serde_json::json!({
        "name": name,
        "inputs": inputs_json(inp),
        "outputs": {
            "zkp_priv": nightfish_honk_ref::bjj_to_dec(&t.zkp_priv),
            "zkp_priv_lambda": fr_to_dec(&t.zkp_priv_lambda),
            "commitments": t.commitments.iter().map(fr_to_dec).collect::<Vec<_>>(),
            "nullifiers": t.nullifiers.iter().map(fr_to_dec).collect::<Vec<_>>(),
            "compressed_secrets": t.compressed_secrets.iter().map(fr_to_dec).collect::<Vec<_>>(),
            "swap_link": fr_to_dec(&t.swap_link),
            "final_fee": fr_to_dec(&t.final_fee),
            "final_root": fr_to_dec(&t.final_root),
            "final_deadline": fr_to_dec(&t.final_deadline),
            "swap_side": fr_to_dec(&t.swap_side),
            "public_inputs": t.public_inputs.iter().map(fr_to_dec).collect::<Vec<_>>(),
        }
    })
}

/// Base inputs: everything padded/zeroed; scenarios override specific fields.
fn transfer_inputs() -> StatementInputs {
    scenarios::transfer_inputs()
}

fn withdraw_inputs() -> StatementInputs {
    scenarios::withdraw_inputs()
}

fn swap_inputs() -> StatementInputs {
    scenarios::swap_inputs()
}

fn deposit_inputs() -> StatementInputs {
    scenarios::deposit_inputs()
}

fn fdec(f: &Fr254) -> String {
    fr_to_dec(f)
}

fn point_nr(p: &Point) -> String {
    format!("Point {{ x: {}, y: {} }}", fdec(&p.x), fdec(&p.y))
}

fn arr_nr(xs: &[Fr254]) -> String {
    let items: Vec<String> = xs.iter().map(fdec).collect();
    format!("[{}]", items.join(", "))
}

fn emit_scenario_nr(name: &str, inp: &StatementInputs) -> String {
    let t = compute_statement(inp);
    let pub_inputs: Vec<String> = t.public_inputs.iter().map(fdec).collect();
    let pks: Vec<String> = inp.public_keys.iter().map(point_nr).collect();
    let sps: Vec<String> = inp.secret_preimages.iter().map(|sp| arr_nr(sp)).collect();
    format!(
        "pub fn {name}() -> (StatementInputs, [Field; NUM_PUBLIC_INPUTS]) {{
    let inp = StatementInputs {{
        root: {root},
        root_key: {root_key},
        zkp_priv: {zkp_priv},
        zkp_priv_lambda: {lambda},
        ephemeral_key: {eph},
        fee_token_id: {fee_token_id},
        fee: {fee},
        nf_address: {nf_address},
        nf_slot_id: {nf_slot_id},
        nullifiers_values: {nv},
        nullifiers_salts: {ns},
        public_keys: [{pk0}, {pk1}, {pk2}, {pk3}],
        membership_proofs: [zp(), zp(), zp(), zp()],
        secret_preimages: [{sp0}, {sp1}, {sp2}, {sp3}],
        commitments_values: {cv},
        sender_commitment_salts: {scs},
        deposit_token_ids: {dti},
        deposit_slot_ids: {dsi},
        deposit_values: {dv},
        deposit_secret_hashes: {dsh},
        withdraw_address: {wa},
        party_a_public_key: {pa},
        party_b_public_key: {pb},
        nf_token_a_id: {ta},
        value_a: {va},
        nf_token_b_id: {tb},
        value_b: {vb},
        swap_nonce: {nonce},
        deadline: {deadline},
    }};
    let expected: [Field; NUM_PUBLIC_INPUTS] = [{pubins}];
    (inp, expected)
}}
",
        name = name,
        root = fdec(&inp.root),
        root_key = fdec(&inp.root_key),
        zkp_priv = nightfish_honk_ref::bjj_to_dec(&t.zkp_priv),
        lambda = fdec(&t.zkp_priv_lambda),
        eph = nightfish_honk_ref::bjj_to_dec(&inp.ephemeral_key),
        fee_token_id = fdec(&inp.fee_token_id),
        fee = fdec(&inp.fee),
        nf_address = fdec(&inp.nf_address),
        nf_slot_id = fdec(&inp.nf_slot_id),
        nv = arr_nr(&inp.nullifiers_values),
        ns = arr_nr(&inp.nullifiers_salts),
        pk0 = pks[0],
        pk1 = pks[1],
        pk2 = pks[2],
        pk3 = pks[3],
        sp0 = sps[0],
        sp1 = sps[1],
        sp2 = sps[2],
        sp3 = sps[3],
        cv = arr_nr(&inp.commitments_values),
        scs = arr_nr(&inp.sender_commitment_salts),
        dti = arr_nr(&inp.deposit_token_ids),
        dsi = arr_nr(&inp.deposit_slot_ids),
        dv = arr_nr(&inp.deposit_values),
        dsh = arr_nr(&inp.deposit_secret_hashes),
        wa = fdec(&inp.withdraw_address),
        pa = point_nr(&inp.party_a_public_key),
        pb = point_nr(&inp.party_b_public_key),
        ta = fdec(&inp.nf_token_a_id),
        va = fdec(&inp.value_a),
        tb = fdec(&inp.nf_token_b_id),
        vb = fdec(&inp.value_b),
        nonce = fdec(&inp.swap_nonce),
        deadline = fdec(&inp.deadline),
        pubins = pub_inputs.join(", "),
    )
}

fn emit_noir(manifest: &std::path::Path, scenarios: &[(&str, StatementInputs)]) {
    let mut body = String::from(
        "//! AUTO-GENERATED by `rust/examples/gen_statement.rs` — do not edit by hand.
//!
//! Frozen full-statement parity vectors (transfer / withdraw / swap), produced
//! from the real `nf_curves` + `jf_primitives` reference oracle.

use crate::bjj::Point;
use crate::merkle::PathElement;
use crate::statement::{StatementInputs, DEPTH, NUM_PUBLIC_INPUTS};

/// A zero-sibling membership path of length DEPTH (leaf at index 0).
pub fn zp() -> [PathElement; DEPTH] {
    [PathElement { sibling: 0, sibling_on_left: false }; DEPTH]
}

",
    );
    for (name, inp) in scenarios {
        body.push_str(&emit_scenario_nr(name, inp));
        body.push('\n');
    }
    let out = manifest.join("../noir/src/statement_vectors.nr");
    std::fs::write(&out, body).expect("write statement_vectors.nr");
    println!("wrote {}", out.display());
}

fn emit_prover_toml(manifest: &std::path::Path, inp: &StatementInputs) {
    let q = |f: &Fr254| format!("\"{}\"", fdec(f));
    let arr = |xs: &[Fr254]| {
        let items: Vec<String> = xs.iter().map(|f| q(f)).collect();
        format!("[{}]", items.join(", "))
    };
    let pt = |p: &Point| format!("{{ x = \"{}\", y = \"{}\" }}", fdec(&p.x), fdec(&p.y));
    let pks: Vec<String> = inp.public_keys.iter().map(pt).collect();
    let sps: Vec<String> = inp.secret_preimages.iter().map(|sp| arr(sp)).collect();
    // Zero-sibling membership paths (one inline table array per slot).
    let path_one = |path: &Vec<PathElement>| {
        let elems: Vec<String> = path
            .iter()
            .map(|e| {
                format!(
                    "{{ sibling = \"{}\", sibling_on_left = {} }}",
                    fdec(&e.sibling),
                    e.sibling_on_left
                )
            })
            .collect();
        format!("[{}]", elems.join(", "))
    };
    let mps: Vec<String> = inp.membership_proofs.iter().map(path_one).collect();

    let toml = format!(
        "# AUTO-GENERATED by `rust/examples/gen_statement.rs` — frozen transfer scenario.
# Regenerate with: cargo run --example gen_statement
[input]
root = {root}
root_key = {root_key}
zkp_priv = {zkp_priv}
zkp_priv_lambda = {lambda}
ephemeral_key = {eph}
fee_token_id = {fee_token_id}
fee = {fee}
nf_address = {nf_address}
nf_slot_id = {nf_slot_id}
nullifiers_values = {nv}
nullifiers_salts = {ns}
public_keys = [{pk0}, {pk1}, {pk2}, {pk3}]
membership_proofs = [{mp0}, {mp1}, {mp2}, {mp3}]
secret_preimages = [{sp0}, {sp1}, {sp2}, {sp3}]
commitments_values = {cv}
sender_commitment_salts = {scs}
deposit_token_ids = {dti}
deposit_slot_ids = {dsi}
deposit_values = {dv}
deposit_secret_hashes = {dsh}
withdraw_address = {wa}
party_a_public_key = {pa}
party_b_public_key = {pb}
nf_token_a_id = {ta}
value_a = {va}
nf_token_b_id = {tb}
value_b = {vb}
swap_nonce = {nonce}
deadline = {deadline}
",
        root = q(&inp.root),
        root_key = q(&inp.root_key),
        zkp_priv = format!("\"{}\"", {
            let (s, _, _) = keys::zkp_private_key_witness(inp.root_key);
            nightfish_honk_ref::bjj_to_dec(&s)
        }),
        lambda = q(&compute_statement(inp).zkp_priv_lambda),
        eph = format!("\"{}\"", nightfish_honk_ref::bjj_to_dec(&inp.ephemeral_key)),
        fee_token_id = q(&inp.fee_token_id),
        fee = q(&inp.fee),
        nf_address = q(&inp.nf_address),
        nf_slot_id = q(&inp.nf_slot_id),
        nv = arr(&inp.nullifiers_values),
        ns = arr(&inp.nullifiers_salts),
        pk0 = pks[0],
        pk1 = pks[1],
        pk2 = pks[2],
        pk3 = pks[3],
        mp0 = mps[0],
        mp1 = mps[1],
        mp2 = mps[2],
        mp3 = mps[3],
        sp0 = sps[0],
        sp1 = sps[1],
        sp2 = sps[2],
        sp3 = sps[3],
        cv = arr(&inp.commitments_values),
        scs = arr(&inp.sender_commitment_salts),
        dti = arr(&inp.deposit_token_ids),
        dsi = arr(&inp.deposit_slot_ids),
        dv = arr(&inp.deposit_values),
        dsh = arr(&inp.deposit_secret_hashes),
        wa = q(&inp.withdraw_address),
        pa = pt(&inp.party_a_public_key),
        pb = pt(&inp.party_b_public_key),
        ta = q(&inp.nf_token_a_id),
        va = q(&inp.value_a),
        tb = q(&inp.nf_token_b_id),
        vb = q(&inp.value_b),
        nonce = q(&inp.swap_nonce),
        deadline = q(&inp.deadline),
    );
    let out = manifest.join("../circuits/client_tx/Prover.toml");
    std::fs::write(&out, toml).expect("write Prover.toml");
    println!("wrote {}", out.display());
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let scenarios = serde_json::json!({
        "depth": scenarios::DEPTH,
        "scenarios": [
            scenario_json("transfer", &transfer_inputs()),
            scenario_json("withdraw", &withdraw_inputs()),
            scenario_json("swap", &swap_inputs()),
            scenario_json("deposit", &deposit_inputs()),
        ]
    });

    let out = manifest.join("../vectors/statement.json");
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&scenarios).unwrap()),
    )
    .expect("write statement.json");
    println!("wrote {}", out.display());

    emit_noir(
        &manifest,
        &[
            ("transfer", transfer_inputs()),
            ("withdraw", withdraw_inputs()),
            ("swap", swap_inputs()),
            ("deposit", deposit_inputs()),
        ],
    );

    emit_prover_toml(&manifest, &transfer_inputs());
}
