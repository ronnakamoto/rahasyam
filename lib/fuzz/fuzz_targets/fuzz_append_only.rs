#![no_main]

use libfuzzer_sys::fuzz_target;
use lib::merkle_trees::trees::helper_functions::{
    make_complete_tree, index_to_directions, get_frontier_index, pow2_usize
};
use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use jf_primitives::poseidon::Poseidon;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 8 {
        return;
    }

    // Extract tree parameters
    let height = (data[0] % 8) as u32; // max height 7 to limit memory/computation in fuzzer
    
    // Extract a random index within bounds
    let max_index = if height > 0 { (1usize << height) - 1 } else { 0 };
    let mut index_bytes = [0u8; 8];
    index_bytes.copy_from_slice(&data[1..9]);
    let index = usize::from_le_bytes(index_bytes) % (max_index + 1);

    // Test pure helpers
    let _ = pow2_usize(height);
    let _ = get_frontier_index(index);
    let _ = index_to_directions(index, height);

    // Extract a leaf value
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[9..41]);
    buf[31] &= 0x0F;
    let leaf = Fr::from_le_bytes_mod_order(&buf);

    let capacity = 1usize << height;
    let mut leaves = vec![Fr::from(0u64); capacity];
    leaves[index] = leaf;

    let hasher = Poseidon::<Fr>::new();
    let tree = make_complete_tree(height, &hasher, &leaves);

    // Ensure the tree array size is 2^(h+1) - 1
    let expected_len = (2usize << height) - 1;
    assert_eq!(tree.len(), expected_len);
});
