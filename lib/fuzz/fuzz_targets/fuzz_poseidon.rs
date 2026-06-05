#![no_main]

use libfuzzer_sys::fuzz_target;
use lib::proving::nova_v1::hash::{poseidon_constants, poseidon_hash2_native, poseidon_hash3_native};
use lib::proving::nova_v1::rollup_engine::F1;
use ff::{PrimeField, Field};

fuzz_target!(|data: &[u8]| {
    // We need at least 96 bytes to extract 3x 32-byte field elements
    if data.len() < 96 {
        return;
    }

    // Safely extract 32-byte chunks and construct field elements, masking
    // to fit within the BN254 prime modulus.
    let mut chunks = [F1::ZERO; 3];
    for (i, chunk) in data.chunks_exact(32).take(3).enumerate() {
        // Create a 256-bit representation
        let mut buf = [0u8; 32];
        buf.copy_from_slice(chunk);
        // Force the high bits down to ensure it is < modulus
        buf[31] &= 0x0F; 
        
        let mut repr = chunks[i].to_repr();
        repr.as_mut().copy_from_slice(&buf);
        chunks[i] = F1::from_repr(repr).unwrap_or(F1::ZERO);
    }

    let constants = poseidon_constants::<F1>();

    // Test hash2
    let _h2 = poseidon_hash2_native(&constants, chunks[0], chunks[1]);

    // Test hash3
    let _h3 = poseidon_hash3_native(&constants, chunks[0], chunks[1], chunks[2]);
});

