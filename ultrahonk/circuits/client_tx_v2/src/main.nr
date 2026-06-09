//! Nightfall programmable-note v2 client-transaction circuit (UltraHonk-provable).
//!
//! Thin binary entry point over the `nightfish_honk` library's v2 transfer
//! statement ([`nightfish_honk::statement_v2::prove_statement_v2`]), the
//! UltraHonk analogue of the v1 `client_tx` circuit but for the fixed 2-in/2-out
//! programmable-note spend.  Compile with `nargo compile`, then prove/verify with
//! Barretenberg UltraHonk (`bb`) or the bb.js harness.
//!
//! Public output: the framed 6-word v2 public-input vector
//! `[framing, root, nullifier_0, nullifier_1, output_commitment_0,
//!   output_commitment_1]`, matching the Rust oracle
//! `statement_v2::compute_statement_v2`.
//!
//! The witness is the full private `StatementV2Inputs`; every constraint
//! (predicate evaluation, owner binding, one-time-key-bound nullifier derivation,
//! membership, per-asset value conservation) is enforced inside the statement and
//! therefore inside this circuit.

use nightfish_honk::statement_v2::{prove_statement_v2, StatementV2Inputs, NUM_PUBLIC_INPUTS_V2};

fn main(input: StatementV2Inputs) -> pub [Field; NUM_PUBLIC_INPUTS_V2] {
    prove_statement_v2(input)
}
