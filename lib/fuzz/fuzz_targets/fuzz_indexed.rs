#![no_main]

use libfuzzer_sys::fuzz_target;
use lib::proving::nova_v1::hash::{poseidon_constants, poseidon_hash3_native};
use lib::proving::nova_v1::merkle::{compute_merkle_root_native, imt_leaf_hash_native, MerklePathHop};
use lib::proving::nova_v1::rollup_engine::F1;
use ff::{PrimeField, Field};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 + 32 * 3 {
        return;
    }

    let constants = poseidon_constants::<F1>();

    // Extract a bounded tree height (0..=6) to keep computation tractable
    let height = (data[0] % 7) as usize;
    let max_leaves = 1usize << height;

    // Helper: extract a field element from byte slice at offset
    let mut extract_f = |offset: usize| -> F1 {
        if offset + 32 > data.len() {
            return F1::ZERO;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[offset..offset + 32]);
        buf[31] &= 0x0F; // force below BN254 modulus
        let mut repr = F1::ZERO.to_repr();
        repr.as_mut().copy_from_slice(&buf);
        F1::from_repr(repr).unwrap_or(F1::ZERO)
    };

    // --- 1. Fuzz IMT leaf hash ---
    let value = extract_f(1);
    let next_index = extract_f(33);
    let next_value = extract_f(65);
    let leaf_hash = imt_leaf_hash_native(&constants, value, next_index, next_value);

    // --- 2. Build a tiny IMT natively and fuzz inclusion ---
    // Use the remaining bytes to seed up to `max_leaves` leaf values.
    let mut leaves = vec![F1::ZERO; max_leaves];
    let mut offset = 97usize;
    for i in 0..max_leaves {
        if offset + 32 <= data.len() {
            leaves[i] = extract_f(offset);
            offset += 32;
        } else {
            break;
        }
    }

    // Compute leaf hashes for the IMT: H(value, next_index, next_value)
    // For fuzzing we use a simple linked-list: each leaf points to the next.
    let mut imt_leaves = vec![F1::ZERO; max_leaves];
    for i in 0..max_leaves {
        let next_idx = F1::from(((i + 1) % max_leaves) as u64);
        let next_val = leaves.get(i + 1).copied().unwrap_or(F1::ZERO);
        imt_leaves[i] = imt_leaf_hash_native(&constants, leaves[i], next_idx, next_val);
    }

    // Build a binary Merkle tree from the IMT leaves and extract a path
    let mut layer = imt_leaves.clone();
    let mut all_layers: Vec<Vec<F1>> = vec![layer.clone()];
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(F1::ZERO);
            next.push(lib::proving::nova_v1::hash::poseidon_hash2_native(&constants, left, right));
        }
        layer = next;
        all_layers.push(layer.clone());
    }
    let root = layer.first().copied().unwrap_or(F1::ZERO);

    // Pick a random leaf index and build a Merkle path for it
    let leaf_idx = if data.len() > 1 {
        (data[1] as usize) % max_leaves.max(1)
    } else {
        0
    };

    let mut path = Vec::with_capacity(height);
    let mut idx = leaf_idx;
    for level in 0..height {
        let current_layer = &all_layers[level];
        let is_right = idx % 2 == 1;
        let sibling = if is_right {
            current_layer.get(idx.wrapping_sub(1)).copied().unwrap_or(F1::ZERO)
        } else {
            current_layer.get(idx + 1).copied().unwrap_or(F1::ZERO)
        };
        path.push(MerklePathHop { sibling, is_right });
        idx /= 2;
    }

    // Verify that the path recomputes to the root
    let recomputed = compute_merkle_root_native(&constants, imt_leaves[leaf_idx], &path);
    assert_eq!(recomputed, root, "Merkle path must recompute to root");
});
