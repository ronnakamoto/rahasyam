//! Nightfall client-transaction circuit (UltraHonk-provable).
//!
//! Thin binary entry point over the `nightfish_honk` library's **full** client
//! statement (transfer / withdraw / swap), the UltraHonk analogue of nf4's
//! `unified_circuit.rs`. Compile with `nargo compile`, then prove/verify with
//! Barretenberg UltraHonk (`bb`) or the `../../ts` bb.js harness.
//!
//! Public output: the framed 27-word public-input vector
//! (`[framing, 1, fee, 1, root, 4, commitments[4], 4, nullifiers[4], 5,
//!   compressed_secrets[5], 1, swap_link, 1, deadline, 1, swap_side]`),
//! matching nf4's `From<&PublicInputs> for Vec<Fr254>`.
//!
//! `Prover.toml` carries the frozen transfer scenario from
//! `../../vectors/statement.json` (regenerate via `rust/examples/gen_statement.rs`).

use nightfish_honk::statement::{NUM_PUBLIC_INPUTS, prove_statement, StatementInputs};

fn main(input: StatementInputs) -> pub [Field; NUM_PUBLIC_INPUTS] {
    prove_statement(input)
}
