//! Ground-truth anchor for the `swap_link` Poseidon sponge.
//!
//! Invokes nf4's **real** `SpongePoseidonHashGadget` (`absorb` + `squeeze`,
//! `jf_primitives::circuit::poseidon::sponge`) on a `PlonkCircuit` — exactly as
//! `unified_circuit.rs:289-305` builds `swap_link` — and reads the witnessed
//! output, then compares it against our native `sponge::hash` reference. This
//! proves the native (and hence the Noir `sponge.nr`) swap-link sponge is
//! bit-for-bit identical to nf4's in-circuit gadget, not just to jf's native
//! `PoseidonSponge` or our own interpretation of it.
//!
//! ```sh
//! cargo run --example anchor_sponge
//! ```

use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use jf_primitives::circuit::poseidon::sponge::{PoseidonStateVar, SpongePoseidonHashGadget};
use jf_relation::{Circuit, PlonkCircuit};
use nightfish_honk_ref::{fr_to_dec, sponge};

/// Build a sponge hash via nf4's real in-circuit gadget and read its witness.
fn gadget_sponge(inputs: &[Fr254]) -> Fr254 {
    let mut circuit = PlonkCircuit::<Fr254>::new_ultra_plonk(16);
    let vars: Vec<_> = inputs
        .iter()
        .map(|x| circuit.create_variable(*x).unwrap())
        .collect();
    // Same initial all-zero width-4 state as unified_circuit.rs:289.
    let initial_state =
        PoseidonStateVar([circuit.zero(), circuit.zero(), circuit.zero(), circuit.zero()]);
    let absorbed = circuit.absorb(&initial_state, &vars).unwrap();
    let out = circuit.squeeze(&absorbed, 1).unwrap()[0];
    circuit.witness(out).unwrap()
}

fn main() {
    // `SWAP_V1` protocol domain, identical to unified_circuit.rs:288.
    let swap_domain = Fr254::from_le_bytes_mod_order(b"SWAP_V1");

    // Representative swap-link tails: [ax, ay, bx, by, tokA, valA, tokB, valB, nonce].
    let cases: [[u64; 9]; 3] = [
        [11, 22, 33, 44, 7, 100, 8, 250, 9],
        [0, 0, 0, 0, 0, 0, 0, 0, 1],
        [
            123_456, 789_012, 345_678, 901_234, 5, 999_999, 6, 888_888, 314_159,
        ],
    ];

    let mut all_ok = true;
    for c in cases {
        let mut inputs = vec![swap_domain];
        for v in c {
            inputs.push(Fr254::from(v));
        }
        let gadget = gadget_sponge(&inputs);
        let native = sponge::hash(&inputs);
        let ok = gadget == native;
        all_ok &= ok;
        println!(
            "inputs (SWAP_V1 + {:?})\n  gadget = {}\n  native = {}\n  => {}",
            c,
            fr_to_dec(&gadget),
            fr_to_dec(&native),
            if ok { "MATCH" } else { "MISMATCH" }
        );
    }

    if !all_ok {
        eprintln!(
            "\nANCHOR FAILED: native sponge::hash diverged from nf4's SpongePoseidonHashGadget"
        );
        std::process::exit(1);
    }
    println!("\nANCHOR OK: native sponge::hash matches nf4's SpongePoseidonHashGadget (swap_link)");
}
