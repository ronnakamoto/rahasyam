//! Standalone Nova attestation service.
//!
//! Stage 1 of the decentralised-attestation roadmap. This service holds
//! the attestor signing key **independently of the proposer** and vouches
//! for Nova block proofs by signing the canonical attestation preimage
//! (see `lib::proving::nova_v1::attestation`). Separating the signer from
//! the prover is the core security improvement: a compromised/buggy
//! proposer can no longer sign its own proofs.
//!
//! ## Trust boundary
//!
//! The service rebuilds the preimage using its **own** view of
//! `chain_id` and the `nova_verifier` address (from its configuration),
//! never values supplied by the caller. This provides domain separation:
//! a malicious proposer cannot trick the attestor into signing a proof
//! bound to a different chain or verifier.
//!
//! ## Verification scope
//!
//! The service runs the **full, sound** Spartan `CompressedSNARK::verify`
//! before signing. Because the proposer rewrites the on-wire roots to
//! their JF values (for the contract's structural check) while the inner
//! SNARK still attests to the **Neptune** roots from the hydrated IVC
//! initial state, the proposer forwards the original Neptune roots and the
//! hydrated `pre_nullifiers_root` (`z0[1]`) alongside the proof. The
//! service reconstructs that pre-root-rewrite statement and verifies it
//! via [`NovaRollupEngine::verify_attestation`]; it signs **only** when
//! verification succeeds (fail-closed). It additionally enforces the
//! structural binding the on-chain verifier checks (roots == public
//! inputs, `snark_proof` length, `transaction_count <= MAX_STEPS`).
//!
//! Running the cryptographic verify requires the Nova public parameters
//! and Spartan verifying key to be available to the service (the same
//! keys the proposer uses); a misconfiguration surfaces as a rejected
//! attestation, never as a signature over an unverified proof.

use alloy::primitives::Address;
use lib::proving::nova_v1::attestation::{
    check_structural_binding, preimage_from_proof, recover_attestor, sign_attestation, SIG_BYTES,
};
use lib::proving::nova_v1::commitment_tree::f1_from_hex;
use lib::proving::nova_v1::proof::NovaProof;
use lib::proving::nova_v1::rollup_engine::NovaRollupEngine;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::panic::AssertUnwindSafe;
use warp::{Filter, Rejection, Reply};

/// JSON request body for `POST /attest`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AttestRequest {
    /// Hex (optionally `0x`-prefixed) of the on-chain bincode `NovaProof`
    /// blob (the bytes the router passes to `verifyProof`, minus the
    /// proving-system-id byte and the appended signature).
    pub proof: String,
    /// Hex (optionally `0x`-prefixed) 32-byte big-endian words for the
    /// four public inputs.
    pub public_inputs: [String; 4],
    /// Hex (optionally `0x`-prefixed) Neptune commitments root
    /// (little-endian) the inner SNARK actually proved (pre root-rewrite).
    pub neptune_commitments_root: String,
    /// Hex (optionally `0x`-prefixed) Neptune nullifiers root
    /// (little-endian).
    pub neptune_nullifiers_root: String,
    /// Hex (optionally `0x`-prefixed) Neptune historic-root root
    /// (little-endian).
    pub neptune_historic_root_root: String,
    /// Hex (optionally `0x`-prefixed) hydrated IVC initial nullifiers root
    /// (`z0[1]`), in `f1_to_hex` (big-endian) encoding.
    pub pre_nullifiers_root: String,
    /// True folded IVC step count (`circuits.len()`); with padding this is
    /// `block_size`, not the proof's `transaction_count`.
    pub num_steps: u64,
}

/// JSON response body for `POST /attest`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AttestResponse {
    /// Hex (`0x`-prefixed) 65-byte `(r || s || v)` signature.
    pub signature: String,
    /// The recovered attestor address (`0x`-prefixed), for the caller to
    /// sanity-check against the configured on-chain attestor.
    pub attestor: String,
}

/// Errors raised while servicing an attestation request.
#[derive(Debug)]
pub enum AttestationServiceError {
    /// No attestor key configured: the service cannot sign.
    NoKey,
    /// The request was malformed (bad hex, wrong length, bad bincode).
    BadRequest(String),
    /// The proof failed structural binding or signing.
    Attestation(String),
}

impl fmt::Display for AttestationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKey => write!(
                f,
                "no attestor key configured (set nova_verifier.attestor_key)"
            ),
            Self::BadRequest(m) => write!(f, "bad request: {m}"),
            Self::Attestation(m) => write!(f, "attestation failed: {m}"),
        }
    }
}

impl std::error::Error for AttestationServiceError {}

/// Successful attestation result.
pub struct Attestation {
    pub signature: [u8; SIG_BYTES],
    pub attestor: Address,
}

fn decode_hex(label: &str, s: &str) -> Result<Vec<u8>, AttestationServiceError> {
    hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| AttestationServiceError::BadRequest(format!("{label} is not valid hex: {e}")))
}

fn decode_word(label: &str, s: &str) -> Result<[u8; 32], AttestationServiceError> {
    let bytes = decode_hex(label, s)?;
    if bytes.len() > 32 {
        return Err(AttestationServiceError::BadRequest(format!(
            "{label} is {} bytes, expected <= 32",
            bytes.len()
        )));
    }
    // Left-pad to a 32-byte big-endian word.
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

/// Decode an exactly-32-byte little-endian root (the Neptune roots are
/// stored little-endian by the prover, so no padding/reordering is
/// applied here).
fn decode_root(label: &str, s: &str) -> Result<[u8; 32], AttestationServiceError> {
    let bytes = decode_hex(label, s)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        AttestationServiceError::BadRequest(format!(
            "{label} must be exactly 32 bytes (got {})",
            bytes.len()
        ))
    })
}

/// Re-run the **sound** Spartan `CompressedSNARK::verify` for the proof in
/// `request`, using the forwarded pre-root-rewrite Neptune roots and
/// hydrated `pre_nullifiers_root`. Returns `Ok(())` only when the proof
/// cryptographically verifies; any other outcome is an error so the
/// service stays **fail-closed** and never signs an unverified proof.
///
/// Panics from key setup (e.g. missing/corrupt public parameters or
/// verifying key) are caught and converted into an error, so a
/// misconfigured service rejects attestations rather than crashing — and,
/// crucially, never produces a signature.
pub fn verify_forwarded_proof(request: &AttestRequest) -> Result<(), AttestationServiceError> {
    let blob = decode_hex("proof", &request.proof)?;
    let proof: NovaProof = bincode::deserialize(&blob).map_err(|e| {
        AttestationServiceError::BadRequest(format!("proof is not a valid NovaProof: {e}"))
    })?;

    let neptune_commitments_root =
        decode_root("neptune_commitments_root", &request.neptune_commitments_root)?;
    let neptune_nullifiers_root =
        decode_root("neptune_nullifiers_root", &request.neptune_nullifiers_root)?;
    let neptune_historic_root_root = decode_root(
        "neptune_historic_root_root",
        &request.neptune_historic_root_root,
    )?;
    let pre_nullifiers_root = f1_from_hex(request.pre_nullifiers_root.trim()).map_err(|e| {
        AttestationServiceError::BadRequest(format!("pre_nullifiers_root: {e}"))
    })?;

    let engine = NovaRollupEngine::new();
    let verified = std::panic::catch_unwind(AssertUnwindSafe(|| {
        engine.verify_attestation(
            &proof.snark_proof,
            &neptune_commitments_root,
            &neptune_nullifiers_root,
            &neptune_historic_root_root,
            proof.transaction_count,
            request.num_steps as usize,
            pre_nullifiers_root,
        )
    }))
    .map_err(|_| {
        AttestationServiceError::Attestation(
            "CompressedSNARK verification panicked (public params / verifying key \
             misconfigured?)"
                .into(),
        )
    })?
    .map_err(|e| {
        AttestationServiceError::Attestation(format!("CompressedSNARK verification error: {e}"))
    })?;

    if !verified {
        return Err(AttestationServiceError::Attestation(
            "CompressedSNARK::verify did not accept the proof".into(),
        ));
    }
    Ok(())
}

/// Core attestation logic, independent of HTTP and of global config so it
/// is unit-testable. Rebuilds the canonical preimage from the **service's
/// own** `chain_id` / `verifier`, enforces the structural binding, and
/// signs with `attestor_key`.
pub fn build_attestation(
    chain_id: u64,
    verifier: Address,
    attestor_key: &str,
    request: &AttestRequest,
) -> Result<Attestation, AttestationServiceError> {
    if attestor_key.trim().is_empty() {
        return Err(AttestationServiceError::NoKey);
    }

    let blob = decode_hex("proof", &request.proof)?;
    let proof: NovaProof = bincode::deserialize(&blob).map_err(|e| {
        AttestationServiceError::BadRequest(format!("proof is not a valid NovaProof: {e}"))
    })?;

    let public_inputs = [
        decode_word("public_inputs[0]", &request.public_inputs[0])?,
        decode_word("public_inputs[1]", &request.public_inputs[1])?,
        decode_word("public_inputs[2]", &request.public_inputs[2])?,
        decode_word("public_inputs[3]", &request.public_inputs[3])?,
    ];

    check_structural_binding(&proof, &public_inputs)
        .map_err(|e| AttestationServiceError::Attestation(e.to_string()))?;

    let preimage = preimage_from_proof(chain_id, verifier, &proof, &public_inputs)
        .map_err(|e| AttestationServiceError::Attestation(e.to_string()))?;
    let signature = sign_attestation(attestor_key, &preimage)
        .map_err(|e| AttestationServiceError::Attestation(e.to_string()))?;
    let attestor = recover_attestor(&preimage, &signature)
        .map_err(|e| AttestationServiceError::Attestation(e.to_string()))?;

    Ok(Attestation {
        signature,
        attestor,
    })
}

/// Configuration captured at service start, injected into the handler.
#[derive(Clone, Copy)]
pub struct AttestorContext {
    pub chain_id: u64,
    pub verifier: Address,
}

/// Build the warp filter graph: `GET /v1/health` and `POST /attest`.
pub fn routes(
    ctx: AttestorContext,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    lib::health_check::health_route().or(attest_route(ctx))
}

fn attest_route(
    ctx: AttestorContext,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::path!("attest")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |request: AttestRequest| handle_attest(ctx, request))
}

fn handle_attest(ctx: AttestorContext, request: AttestRequest) -> warp::reply::Response {
    use warp::http::StatusCode;

    let attestor_key = configuration::settings::get_settings()
        .nova_verifier
        .attestor_key
        .clone();

    // Fail-closed: re-run the sound `CompressedSNARK::verify` BEFORE
    // signing. The service never vouches for a proof it has not
    // cryptographically verified.
    if let Err(e) = verify_forwarded_proof(&request) {
        let status = match e {
            AttestationServiceError::NoKey => StatusCode::SERVICE_UNAVAILABLE,
            AttestationServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AttestationServiceError::Attestation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        log::warn!("[attestor] rejecting attestation (verification): {e}");
        return warp::reply::with_status(
            warp::reply::json(&serde_json::json!({ "error": e.to_string() })),
            status,
        )
        .into_response();
    }

    match build_attestation(ctx.chain_id, ctx.verifier, &attestor_key, &request) {
        Ok(att) => {
            let body = AttestResponse {
                signature: format!("0x{}", hex::encode(att.signature)),
                attestor: att.attestor.to_checksum(None),
            };
            warp::reply::with_status(warp::reply::json(&body), StatusCode::OK).into_response()
        }
        Err(e) => {
            let status = match e {
                AttestationServiceError::NoKey => StatusCode::SERVICE_UNAVAILABLE,
                AttestationServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
                AttestationServiceError::Attestation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            };
            log::warn!("[attestor] rejecting attestation: {e}");
            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({ "error": e.to_string() })),
                status,
            )
            .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib::proving::nova_v1::attestation::attestation_preimage;

    const ATTESTOR_KEY: &str = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";

    fn synth_proof(snark_len: usize, tx_count: usize) -> NovaProof {
        NovaProof {
            snark_proof: vec![9u8; snark_len],
            commitments_root: vec![0x11u8; 32],
            nullifiers_root: vec![0x22u8; 32],
            historic_root_root: vec![0x33u8; 32],
            transaction_count: tx_count,
        }
    }

    fn request_for(proof: &NovaProof, block_len: u64) -> AttestRequest {
        let blob = bincode::serialize(proof).unwrap();
        AttestRequest {
            proof: format!("0x{}", hex::encode(&blob)),
            public_inputs: [
                format!("0x{}", hex::encode(&proof.commitments_root)),
                format!("0x{}", hex::encode(&proof.nullifiers_root)),
                format!("0x{}", hex::encode(&proof.historic_root_root)),
                format!("0x{}", hex::encode(block_len.to_be_bytes())),
            ],
            // Synthetic Neptune roots + zero z0[1]; only the cryptographic
            // verify path consumes these, and the synthetic `snark_proof`
            // is rejected before they matter.
            neptune_commitments_root: format!("0x{}", hex::encode([0x11u8; 32])),
            neptune_nullifiers_root: format!("0x{}", hex::encode([0x22u8; 32])),
            neptune_historic_root_root: format!("0x{}", hex::encode([0x33u8; 32])),
            pre_nullifiers_root: format!("0x{}", hex::encode([0u8; 32])),
            num_steps: proof.transaction_count as u64,
        }
    }

    #[test]
    fn build_attestation_signs_consistent_proof() {
        let chain_id = 31337u64;
        let verifier = Address::from([0xCDu8; 20]);
        let proof = synth_proof(96, 20);
        let req = request_for(&proof, 64);

        let att = build_attestation(chain_id, verifier, ATTESTOR_KEY, &req).unwrap();

        // The recovered attestor must match the key, and the signature
        // must verify against the exact preimage the contract rebuilds.
        let mut block_len_word = [0u8; 32];
        block_len_word[24..].copy_from_slice(&64u64.to_be_bytes());
        let pi = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            block_len_word,
        ];
        let preimage = attestation_preimage(
            chain_id,
            verifier,
            &proof.snark_proof,
            &[0x11u8; 32],
            &[0x22u8; 32],
            &[0x33u8; 32],
            20,
            &pi,
        );
        let recovered = recover_attestor(&preimage, &att.signature).unwrap();
        assert_eq!(recovered, att.attestor);
    }

    #[test]
    fn build_attestation_rejects_tampered_public_inputs() {
        let proof = synth_proof(96, 20);
        let mut req = request_for(&proof, 64);
        // Corrupt publicInputs[0] so it no longer matches the proof root.
        req.public_inputs[0] = format!("0x{}", hex::encode([0xEEu8; 32]));
        let res = build_attestation(31337, Address::ZERO, ATTESTOR_KEY, &req);
        assert!(matches!(res, Err(AttestationServiceError::Attestation(_))));
    }

    #[test]
    fn build_attestation_requires_key() {
        let proof = synth_proof(96, 20);
        let req = request_for(&proof, 64);
        let res = build_attestation(31337, Address::ZERO, "", &req);
        assert!(matches!(res, Err(AttestationServiceError::NoKey)));
    }

    #[test]
    fn verify_forwarded_proof_rejects_unverifiable_proof() {
        // A synthetic `snark_proof` is far too small to be a real
        // CompressedSNARK; the fail-fast guard rejects it before any keyed
        // setup, so the service refuses to sign (fail-closed).
        let proof = synth_proof(96, 20);
        let req = request_for(&proof, 64);
        let res = verify_forwarded_proof(&req);
        assert!(
            matches!(res, Err(AttestationServiceError::Attestation(_))),
            "expected fail-closed rejection, got {res:?}"
        );
    }

    #[tokio::test]
    async fn attest_route_is_fail_closed_for_unverifiable_proof() {
        let ctx = AttestorContext {
            chain_id: 31337,
            verifier: Address::from([0xCDu8; 20]),
        };
        // Synthetic proof cannot pass `CompressedSNARK::verify`, so the
        // route must NOT return a signature (200). It rejects at the
        // verification stage (422) regardless of whether a key is set.
        let proof = synth_proof(96, 20);
        let req = request_for(&proof, 64);
        let resp = warp::test::request()
            .method("POST")
            .path("/attest")
            .json(&req)
            .reply(&routes(ctx))
            .await;
        assert_eq!(
            resp.status(),
            warp::http::StatusCode::UNPROCESSABLE_ENTITY,
            "service must be fail-closed for an unverifiable proof; got {}",
            resp.status()
        );
    }
}
