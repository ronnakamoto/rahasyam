//! Ground-truth anchor for the deposit SHA256 hash.
//!
//! Invokes nf4's **real** `full_shifted_sha256_hash` gadget (from
//! `jf_primitives::circuit::sha256`) on a known input and reads the witnessed
//! output, then compares it against our native `sha256_shift` reference. This
//! proves the native (and hence Noir) deposit hashing is bit-for-bit identical
//! to nf4's in-circuit gadget — not just to our own interpretation of it.
//!
//! ```sh
//! cargo run --example anchor_sha256
//! ```

use ark_bn254::Fr as Fr254;
use jf_primitives::circuit::sha256::Sha256HashGadget;
use jf_relation::{Circuit, PlonkCircuit};
use nightfish_honk_ref::{deposit, fr_to_dec};

fn gadget_shifted_sha256(inputs: &[Fr254]) -> Fr254 {
    let mut circuit = PlonkCircuit::<Fr254>::new_ultra_plonk(16);
    let vars: Vec<_> = inputs
        .iter()
        .map(|x| circuit.create_variable(*x).unwrap())
        .collect();
    let mut lookup_vars = Vec::new();
    // `.1` is the top-252-bit (>>4) output used as deposit public data.
    let (_low, acc) = circuit
        .full_shifted_sha256_hash(&vars, &mut lookup_vars)
        .unwrap();
    circuit.witness(acc).unwrap()
}

fn main() {
    let cases: [[u64; 4]; 3] = [
        [7, 3, 1000, 424242],
        [1, 0, 0, 1],
        [9_999_999, 12_345, 88_888_888, 314_159_265],
    ];

    let mut all_ok = true;
    for c in cases {
        let inputs = [
            Fr254::from(c[0]),
            Fr254::from(c[1]),
            Fr254::from(c[2]),
            Fr254::from(c[3]),
        ];
        let gadget = gadget_shifted_sha256(&inputs);
        let native = deposit::sha256_shift(&inputs);
        let ok = gadget == native;
        all_ok &= ok;
        println!(
            "inputs {:?}\n  gadget = {}\n  native = {}\n  => {}",
            c,
            fr_to_dec(&gadget),
            fr_to_dec(&native),
            if ok { "MATCH" } else { "MISMATCH" }
        );
    }

    if !all_ok {
        eprintln!("ANCHOR FAILED: native sha256_shift != nf4 gadget");
        std::process::exit(1);
    }
    println!("\nANCHOR OK: native sha256_shift matches nf4's full_shifted_sha256_hash gadget");
}
