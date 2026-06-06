//! Proposer-side attestation client.
//!
//! Stage 1 of the decentralised-attestation roadmap separates *signing*
//! from *proving*. The proposer no longer holds the attestor key by
//! default: it asks a standalone attestation service
//! (`nightfall_attestor`) to vouch for a Nova proof and append the
//! resulting signature.
//!
//! Resolution order:
//!   1. If `nightfall_attestor.url` is configured, POST the on-chain
//!      `NovaProof` blob + public inputs to `{url}/attest` and use the
//!      returned signature. The service rebuilds the canonical preimage
//!      with *its own* chain-id / verifier address (domain separation,
//!      so a malicious proposer cannot retarget the signature) and signs
//!      with its independent key.
//!   2. Otherwise, if `nova_verifier.attestor_key` is set, sign locally
//!      (single-signer dev path; preserves existing `nf4_test`
//!      behaviour).
//!   3. Otherwise, emit an unsigned proof (the on-chain verifier is
//!      fail-closed and will reject it).

use crate::driven::rollup_prover::RollupProofError;
use lib::proving::nova_v1::attestation::{preimage_from_proof, sign_attestation, SIG_BYTES};
use lib::proving::nova_v1::commitment_tree::f1_to_hex;
use lib::proving::nova_v1::proof::NovaProof;
use lib::proving::nova_v1::rollup_engine::{NovaRollupEngine, F1};
use log::{info, warn};
use serde::{Deserialize, Serialize};

/// The pre-root-rewrite data the attestor needs to re-run the sound
/// `CompressedSNARK::verify`. The on-chain `NovaProof` carries JF roots,
/// but the inner SNARK proves the **Neptune** roots from the hydrated IVC
/// initial state, so the attestor must be handed those original values.
pub struct ForwardedVerification {
    /// Neptune commitments root (little-endian, as the SNARK proved it).
    pub neptune_commitments_root: Vec<u8>,
    /// Neptune nullifiers root (little-endian).
    pub neptune_nullifiers_root: Vec<u8>,
    /// Neptune historic-root root (little-endian).
    pub neptune_historic_root_root: Vec<u8>,
    /// Hydrated IVC initial nullifiers root (`z0[1]`).
    pub pre_nullifiers_root: F1,
    /// True folded IVC step count (`circuits.len()`). With padding (the
    /// default, non-dynamic block size) this is `block_size`, NOT the
    /// real `transaction_count`; the attestor needs it to replay the
    /// folding hash, so verification of padded blocks succeeds.
    pub num_steps: usize,
}

/// Outcome of an attestation request.
pub enum AttestationOutcome {
    /// A 65-byte `(r || s || v)` attestor signature to append to the
    /// rollup proof.
    Signed([u8; SIG_BYTES]),
    /// No attestor configured: the proof is emitted unsigned (and will
    /// be rejected on-chain).
    Unsigned,
}

#[derive(Debug, Serialize)]
struct AttestRequest {
    /// Hex (0x-prefixed) of the on-chain bincode `NovaProof` blob.
    proof: String,
    /// Hex (0x-prefixed) 32-byte big-endian words for the four public
    /// inputs `[commitments_root, nullifiers_root, historic_root_root,
    /// block_len]`.
    public_inputs: [String; 4],
    /// Hex (0x-prefixed) Neptune commitments root (little-endian) the
    /// inner SNARK actually proved.
    neptune_commitments_root: String,
    /// Hex (0x-prefixed) Neptune nullifiers root (little-endian).
    neptune_nullifiers_root: String,
    /// Hex (0x-prefixed) Neptune historic-root root (little-endian).
    neptune_historic_root_root: String,
    /// Hex (0x-prefixed) hydrated IVC initial nullifiers root (`z0[1]`),
    /// in `f1_to_hex` (big-endian) encoding.
    pre_nullifiers_root: String,
    /// True folded IVC step count (`circuits.len()`).
    num_steps: u64,
}

#[derive(Debug, Deserialize)]
struct AttestResponse {
    /// Hex (0x-prefixed) 65-byte signature.
    signature: String,
    /// Optional attestor address, for logging.
    #[serde(default)]
    attestor: Option<String>,
}

fn err<E: std::fmt::Display>(ctx: &str, e: E) -> RollupProofError {
    RollupProofError::ParameterError(format!("{ctx}: {e}"))
}

fn parse_signature(hex_sig: &str) -> Result<[u8; SIG_BYTES], RollupProofError> {
    let bytes = hex::decode(hex_sig.trim().trim_start_matches("0x"))
        .map_err(|e| err("attestor signature is not valid hex", e))?;
    <[u8; SIG_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
        RollupProofError::ParameterError(format!(
            "attestor signature must be {SIG_BYTES} bytes"
        ))
    })
}

/// Obtain an attestation for `proof` (whose on-chain bincode is `blob`)
/// bound to `public_inputs`. `verification` carries the pre-root-rewrite
/// data the attestor uses to re-run the sound `CompressedSNARK::verify`
/// before vouching for the proof.
pub async fn obtain_attestation(
    proof: &NovaProof,
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
    verification: &ForwardedVerification,
) -> Result<AttestationOutcome, RollupProofError> {
    let settings = configuration::settings::get_settings();
    let url = settings.nightfall_attestor.url.trim();

    if !url.is_empty() {
        return obtain_remote(url, blob, public_inputs, verification).await;
    }

    let attestor_key = settings.nova_verifier.attestor_key.trim();
    if attestor_key.is_empty() {
        warn!(
            "[attestor_client] No attestation service URL and no \
             nova_verifier.attestor_key configured; emitting an unsigned \
             Nova proof. The on-chain NovaRollupVerifier is fail-closed \
             and will reject it."
        );
        return Ok(AttestationOutcome::Unsigned);
    }

    // Local single-signer path: still fail-closed. Re-run the sound
    // `CompressedSNARK::verify` before signing so the local signer never
    // vouches for a proof it has not cryptographically verified.
    let verified = NovaRollupEngine::new()
        .verify_attestation(
            &proof.snark_proof,
            &verification.neptune_commitments_root,
            &verification.neptune_nullifiers_root,
            &verification.neptune_historic_root_root,
            proof.transaction_count,
            verification.num_steps,
            verification.pre_nullifiers_root,
        )
        .map_err(|e| err("verifying proof before local signing", e))?;
    if !verified {
        return Err(RollupProofError::ParameterError(
            "local attestation refused: CompressedSNARK::verify did not accept the proof".into(),
        ));
    }

    let addresses = configuration::addresses::get_addresses();
    let preimage = preimage_from_proof(
        addresses.chain_id,
        addresses.nova_verifier,
        proof,
        public_inputs,
    )
    .map_err(|e| err("building attestation preimage", e))?;
    let signature = sign_attestation(attestor_key, &preimage)
        .map_err(|e| err("signing attestation locally", e))?;
    info!(
        "[attestor_client] Verified CompressedSNARK and signed proof locally \
         with nova_verifier.attestor_key"
    );
    Ok(AttestationOutcome::Signed(signature))
}

async fn obtain_remote(
    url: &str,
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
    verification: &ForwardedVerification,
) -> Result<AttestationOutcome, RollupProofError> {
    let endpoint = format!("{}/attest", url.trim_end_matches('/'));
    let request = AttestRequest {
        proof: format!("0x{}", hex::encode(blob)),
        public_inputs: [
            format!("0x{}", hex::encode(public_inputs[0])),
            format!("0x{}", hex::encode(public_inputs[1])),
            format!("0x{}", hex::encode(public_inputs[2])),
            format!("0x{}", hex::encode(public_inputs[3])),
        ],
        neptune_commitments_root: format!(
            "0x{}",
            hex::encode(&verification.neptune_commitments_root)
        ),
        neptune_nullifiers_root: format!(
            "0x{}",
            hex::encode(&verification.neptune_nullifiers_root)
        ),
        neptune_historic_root_root: format!(
            "0x{}",
            hex::encode(&verification.neptune_historic_root_root)
        ),
        pre_nullifiers_root: f1_to_hex(&verification.pre_nullifiers_root),
        num_steps: verification.num_steps as u64,
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(&endpoint)
        .json(&request)
        .send()
        .await
        .map_err(|e| err(&format!("calling attestation service at {endpoint}"), e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(RollupProofError::ParameterError(format!(
            "attestation service {endpoint} returned {status}: {body}"
        )));
    }

    let parsed: AttestResponse = resp
        .json()
        .await
        .map_err(|e| err("decoding attestation service response", e))?;
    let signature = parse_signature(&parsed.signature)?;
    info!(
        "[attestor_client] Obtained attestation from {} (attestor: {})",
        endpoint,
        parsed.attestor.as_deref().unwrap_or("unknown")
    );
    Ok(AttestationOutcome::Signed(signature))
}
