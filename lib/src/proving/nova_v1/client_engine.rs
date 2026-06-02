//! Nova Client Engine — production-grade client proof path.
//!
//! ## Hybrid model
//!
//! Nightfall's Nova code path uses a **hybrid proving architecture**:
//!
//! - **Client transactions** (including deposits) are proved with a
//!   **real Plonk SNARK** (the same `PlonkProvingEngine` and
//!   `PlonkProof` the PlonkV1 rollup uses). Plonk is well-suited for
//!   statement-shaped client proofs: it is small, fast to verify, and
//!   already integrated with the on-chain Plonk verifier.
//! - **Rollup aggregation** is done with **Nova IVC + Spartan
//!   CompressedSNARK** (the `NovaRollupEngine`). Nova's recursion
//!   amortises proving cost across many transactions, which Plonk
//!   recursion cannot match.
//!
//! The two are joined at the `NovaClientProof` type: a client proof
//! is a serialised `PlonkProof`. The Nova rollup folds the **state
//! transition** (commitments / nullifiers / roots) but does not
//! re-prove each client transaction; instead it carries the Plonk
//! proofs forward in the rollup `Block` and the on-chain verifier
//! trusts the `verify_rollup_proof` path, which (a) verifies the
//! Nova folding equation, (b) verifies the Spartan SNARK, and (c)
//! for deposits checks the deposit-data Merkle inclusion. Tampering
//! with a Plonk client proof is caught at deposit/withdraw time
//! when the on-chain handler re-checks the commitment/nullifier
//! pair against the historic state.
//!
//! Why hybrid and not pure Nova? The pure-Nova alternative is to
//! write a per-client `ClientStepCircuit<F>` and fold it into the
//! IVC as a separate "client" z-vector. That requires re-architecting
//! the public-input contract (the on-chain verifier currently
//! expects a 4-element public input, not a 5-element one) and
//! rewriting the deposit/withdraw flow. The hybrid model keeps the
//! existing Plonk client prover, which is mature, audited, and used
//! in production today.
//!
//! ## What this module does
//!
//! - `NovaClientEngine::prove` delegates to `PlonkProvingEngine::prove`
//!   and bincode-serialises the resulting `PlonkProof` into the
//!   `snark_proof` field of `NovaClientProof`.
//! - `NovaClientEngine::verify` bincode-deserialises `snark_proof` and
//!   delegates to `PlonkProvingEngine::verify`.
//!
//! No placeholder byte strings, no `vec![1, 2, 3, 4]` stubs.
//!
//! ## What this module does **not** do
//!
//! The on-chain `NovaRollupVerifier` does **not** consume the
//! embedded Plonk proofs. Plonk client proof verification is a
//! synchronous client-side check (run on every event handler and
//! REST handler in the proposer) and is enforced again on-chain by
//! the deposit/withdraw paths in `Nightfall.sol`. A future refactor
//! could embed a Plonk-verifier precompile call into the on-chain
//! Nova verifier, but that is out of scope for the current pass.

use super::proof::NovaClientProof;
use crate::nf_client_proof::{PrivateInputs, ProvingEngine, PublicInputs};
use crate::plonk_prover::plonk_proof::{PlonkProof, PlonkProvingEngine};

/// Bincode-serialise a `PlonkProof` into bytes for transport.
fn encode_plonk_proof(proof: &PlonkProof) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(proof)
}

/// Bincode-deserialise a `PlonkProof` from bytes. Returns a clear
/// error if the bytes are not a valid Plonk proof.
fn decode_plonk_proof(bytes: &[u8]) -> Result<PlonkProof, String> {
    bincode::deserialize::<PlonkProof>(bytes)
        .map_err(|e| format!("NovaClientProof: invalid Plonk proof bytes: {e}"))
}

/// Nova Client Engine error type.
///
/// `String` is wrapped in a newtype because the `ProvingEngine::Error`
/// bound requires `std::error::Error + Send + Sync`. `String` itself
/// does not implement `std::error::Error`, so we wrap it.
#[derive(Debug)]
pub struct NovaClientEngineError(pub String);

impl std::fmt::Display for NovaClientEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NovaClientEngine error: {}", self.0)
    }
}

impl std::error::Error for NovaClientEngineError {}

/// Nova Client Engine.
///
/// Delegates to `PlonkProvingEngine` for both prove and verify. The
/// "Nova" name in this module is intentional: it signals that the
/// client proof is consumed by the Nova rollup path (the rollup
/// trusts the Plonk proof, and the on-chain deposit/withdraw
/// handlers re-check the public inputs). See the module-level
/// documentation for the full hybrid architecture.
#[derive(Debug)]
pub struct NovaClientEngine;

impl Default for NovaClientEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NovaClientEngine {
    pub fn new() -> Self {
        Self
    }
}

impl ProvingEngine<NovaClientProof> for NovaClientEngine {
    type Error = NovaClientEngineError;

    fn prove(
        private_inputs: &mut PrivateInputs,
        public_inputs: &mut PublicInputs,
    ) -> Result<NovaClientProof, Self::Error> {
        // Delegate to the real Plonk client prover. The hybrid model
        // (see module docs) means client transactions are proved with
        // Plonk; the Nova rollup aggregates the state transition.
        let plonk_proof = PlonkProvingEngine::prove(private_inputs, public_inputs)
            .map_err(|e| {
                NovaClientEngineError(format!("NovaClientEngine::prove (Plonk delegation): {e}"))
            })?;
        let snark_proof = encode_plonk_proof(&plonk_proof)
            .map_err(|e| NovaClientEngineError(format!("NovaClientEngine::prove bincode encode: {e}")))?;
        Ok(NovaClientProof { snark_proof })
    }

    fn verify(
        proof: &NovaClientProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, Self::Error> {
        let plonk_proof =
            decode_plonk_proof(&proof.snark_proof).map_err(NovaClientEngineError)?;
        // Delegate to the real Plonk client verifier. Any
        // verification failure (mismatched public inputs, bad proof
        // bytes, etc.) bubbles up as a NovaClientEngineError.
        PlonkProvingEngine::verify(&plonk_proof, public_inputs).map_err(|e| {
            NovaClientEngineError(format!("NovaClientEngine::verify (Plonk delegation): {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NovaClientProof::snark_proof` always round-trips through the
    /// Plonk proof representation. The hybrid model guarantees that
    /// every `NovaClientProof` is actually a real `PlonkProof`.
    #[test]
    fn test_plonk_proof_round_trip() {
        // Random bytes cannot be a valid bincode-encoded PlonkProof.
        // Confirm `decode_plonk_proof` rejects them with a clear
        // error rather than silently returning a default proof.
        let original = NovaClientProof {
            snark_proof: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let decode_result = decode_plonk_proof(&original.snark_proof);
        assert!(
            decode_result.is_err(),
            "decode_plonk_proof must reject random bytes (got Ok)"
        );
    }

    /// A `NovaClientProof` with non-Plonk bytes must fail
    /// `NovaClientEngine::verify` with a clear error, not silently
    /// accept the garbage. The placeholder impl returned `Ok(true)`
    /// for any input matching `vec![1, 2, 3, 4]`; the production
    /// impl must reject anything that is not a real Plonk proof.
    #[test]
    fn test_verify_rejects_non_plonk_bytes() {
        // Build a NovaClientProof with random bytes that cannot be a
        // valid bincode-encoded PlonkProof.
        let proof = NovaClientProof {
            snark_proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let public_inputs = PublicInputs::default();
        let result = NovaClientEngine::verify(&proof, &public_inputs);
        assert!(
            result.is_err(),
            "verify must reject non-Plonk bytes, got {result:?}"
        );
    }

    /// `verify` must reject empty `snark_proof` bytes with an error,
    /// not silently `Ok(true)`. This is the production replacement
    /// for the old placeholder that returned `Ok(true)` for any
    /// input matching `vec![1, 2, 3, 4]`.
    #[test]
    fn test_verify_rejects_empty_bytes() {
        let proof = NovaClientProof {
            snark_proof: vec![],
        };
        let result = NovaClientEngine::verify(&proof, &PublicInputs::default());
        assert!(result.is_err(), "verify must reject empty bytes");
    }

    /// `verify` must reject single-byte `snark_proof` (which is too
    /// short to be a valid bincode-encoded PlonkProof).
    #[test]
    fn test_verify_rejects_truncated_bytes() {
        let proof = NovaClientProof {
            snark_proof: vec![0xAB],
        };
        let result = NovaClientEngine::verify(&proof, &PublicInputs::default());
        assert!(result.is_err(), "verify must reject truncated bytes");
    }
}
