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
use lib::proving::nova_v1::proof::NovaProof;
use log::{info, warn};
use serde::{Deserialize, Serialize};

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
/// bound to `public_inputs`.
pub async fn obtain_attestation(
    proof: &NovaProof,
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
) -> Result<AttestationOutcome, RollupProofError> {
    let settings = configuration::settings::get_settings();
    let url = settings.nightfall_attestor.url.trim();

    if !url.is_empty() {
        return obtain_remote(url, blob, public_inputs).await;
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
    info!("[attestor_client] Signed proof locally with nova_verifier.attestor_key");
    Ok(AttestationOutcome::Signed(signature))
}

async fn obtain_remote(
    url: &str,
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
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
