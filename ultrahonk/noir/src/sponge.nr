//! Poseidon sponge (state width 4, rate 3).
//!
//! Matches Nightfish's `SpongePoseidonHashGadget` (`jf_primitives`, paired native
//! impl `PoseidonSponge<F, 3>`), used to build the swap-link hash
//! (`nf4 lib/src/plonk_prover/circuits/unified_circuit.rs:289-305`).
//!
//! The state is four field elements with the **capacity at index 0**. Inputs are
//! absorbed in chunks of 3 into positions `[1, 2, 3]`, applying the width-4
//! Poseidon permutation (`poseidon::poseidon::bn254::perm::x5_4`, the same
//! permutation that backs `hash_3`) after each chunk. A single squeeze returns
//! `state[0]`.
//!
//! Parity with the fixed-arity Poseidon is anchored two ways: a one-chunk sponge
//! equals `hash3` (asserted in `tests.nr`), and the 10-input swap-link value is
//! frozen from the real `jf_primitives` sponge (see `../../rust`).

use poseidon::poseidon::bn254::perm;

/// Absorb `inputs` in rate-3 chunks and squeeze one field element.
pub fn hash<let N: u32>(inputs: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0; 4];
    let num_chunks = (N + 2) / 3;
    for c in 0..num_chunks {
        for k in 0..3 {
            let idx = c * 3 + k;
            if idx < N {
                state[1 + k] += inputs[idx];
            }
        }
        state = perm::x5_4(state);
    }
    state[0]
}
