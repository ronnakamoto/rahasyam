//! Generate BLS12-381 keypairs for the Nova attestor committee (plan B3).
//!
//! Run:
//!   cargo run -p lib --features nova-bls --example bls_committee_keygen -- [N]
//!
//! For each of `N` members it prints:
//!   - `bls_secret_key` — set on that member's `nightfall_attestor` node
//!     (`nova_verifier.bls_secret_key`). Keep OFFLINE / out-of-band.
//!   - `pubkey` — the on-chain registry key (deploy `pubkeys[i]`) and the
//!     proposer's `committee_members[i].pubkey`.
//!   - `pop` — the proof-of-possession the deploy script passes to
//!     `addAttestor(pubkey, pop)`.
//!
//! The member ORDER is the on-chain registry order: bitmap bit `i` selects
//! `pubkeys[i]`, so keep the lists aligned across deploy, proposer, and nodes.

use lib::proving::nova_v1::bls::SecretKey;
use rand::RngCore;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(3);
    // Deterministic mode (reproducible dev committees): `... -- <N> deterministic`.
    let deterministic = args.iter().any(|a| a == "deterministic");

    let mut rng = rand::rngs::OsRng;
    println!("# BLS committee keys (N={n}). Keep secret keys OFFLINE / out-of-band.");
    for i in 0..n {
        let mut ikm = [0u8; 32];
        if deterministic {
            // Fixed per-index seed; reproducible across runs (dev/test only).
            ikm = [0xD0u8.wrapping_add(i as u8); 32];
        } else {
            rng.fill_bytes(&mut ikm);
        }
        let sk = SecretKey::from_ikm(&ikm).expect("keygen");
        println!("\n# member {i}");
        println!("bls_secret_key = \"0x{}\"", hexs(&sk.to_bytes()));
        println!("pubkey         = \"0x{}\"", hexs(&sk.public_key()));
        println!("pop            = \"0x{}\"", hexs(&sk.proof_of_possession()));
    }
}
