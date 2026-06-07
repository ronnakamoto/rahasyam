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
use lib::proving::nova_v1::bls;
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
    /// rollup proof (single-attestor ECDSA gate, proof-system id `NovaV1`).
    Signed([u8; SIG_BYTES]),
    /// An aggregate BLS committee signature to append: `sigma` (256-byte G2)
    /// followed by `bitmap` (32-byte big-endian signer set). Verified on-chain
    /// by `NovaCommitteeVerifier` (proof-system id `NovaBlsV1`).
    Committee {
        sigma: [u8; bls::SIG_BYTES],
        bitmap: [u8; 32],
    },
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
    /// Hex (0x-prefixed) 256-byte EIP-2537 BLS signature share (committee mode).
    #[serde(default)]
    bls_share: Option<String>,
    /// Hex (0x-prefixed) 128-byte EIP-2537 BLS public key for the share.
    #[serde(default)]
    bls_pubkey: Option<String>,
}

fn err<E: std::fmt::Display>(ctx: &str, e: E) -> RollupProofError {
    RollupProofError::ParameterError(format!("{ctx}: {e}"))
}

fn parse_signature(hex_sig: &str) -> Result<[u8; SIG_BYTES], RollupProofError> {
    let bytes = hex::decode(hex_sig.trim().trim_start_matches("0x"))
        .map_err(|e| err("attestor signature is not valid hex", e))?;
    <[u8; SIG_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
        RollupProofError::ParameterError(format!("attestor signature must be {SIG_BYTES} bytes"))
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
    let nova = &settings.nova_verifier;

    // Committee gate (proof-system id NovaBlsV1) takes precedence when configured.
    if nova.committee_threshold > 0 && !nova.committee_members.is_empty() {
        return obtain_committee(
            &nova.committee_members,
            nova.committee_threshold,
            blob,
            public_inputs,
            verification,
        )
        .await;
    }

    let url = settings.nightfall_attestor.url.trim();

    if !url.is_empty() {
        return obtain_remote(url, blob, public_inputs, verification).await;
    }

    let attestor_key = nova.attestor_key.trim();
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
    let request = build_attest_request(blob, public_inputs, verification);

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

/// Build the `/attest` request body shared by the single-service and committee
/// paths.
fn build_attest_request(
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
    verification: &ForwardedVerification,
) -> AttestRequest {
    AttestRequest {
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
    }
}

fn parse_pubkey(hex_pk: &str) -> Result<[u8; bls::PUBKEY_BYTES], RollupProofError> {
    let bytes = hex::decode(hex_pk.trim().trim_start_matches("0x"))
        .map_err(|e| err("committee bls_pubkey is not valid hex", e))?;
    <[u8; bls::PUBKEY_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
        RollupProofError::ParameterError(format!(
            "committee bls_pubkey must be {} bytes",
            bls::PUBKEY_BYTES
        ))
    })
}

fn parse_share(hex_sig: &str) -> Result<[u8; bls::SIG_BYTES], RollupProofError> {
    let bytes = hex::decode(hex_sig.trim().trim_start_matches("0x"))
        .map_err(|e| err("committee bls_share is not valid hex", e))?;
    <[u8; bls::SIG_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
        RollupProofError::ParameterError(format!(
            "committee bls_share must be {} bytes",
            bls::SIG_BYTES
        ))
    })
}

/// Aggregate collected `(index, share)` pairs into `(sigma, bitmap)`. The
/// bitmap is a 32-byte big-endian word with bit `i` set for signer `i`,
/// matching the on-chain `bitmap & (1 << i)` over `pubkeys[i]`. Fails closed if
/// fewer than `threshold` shares were collected.
pub fn assemble_committee_signature(
    shares: &[(usize, [u8; bls::SIG_BYTES])],
    threshold: usize,
) -> Result<([u8; bls::SIG_BYTES], [u8; 32]), RollupProofError> {
    if shares.len() < threshold {
        return Err(RollupProofError::ParameterError(format!(
            "committee attestation refused: collected {} shares < threshold {}",
            shares.len(),
            threshold
        )));
    }
    let sigs: Vec<[u8; bls::SIG_BYTES]> = shares.iter().map(|(_, s)| *s).collect();
    let sigma = bls::aggregate_signatures(&sigs)
        .map_err(|e| err("aggregating committee signature shares", e))?;

    let mut bitmap = [0u8; 32];
    for (idx, _) in shares {
        if *idx >= 256 {
            return Err(RollupProofError::ParameterError(format!(
                "committee signer index {idx} out of range"
            )));
        }
        bitmap[31 - (idx / 8)] |= 1u8 << (idx % 8);
    }
    Ok((sigma, bitmap))
}

async fn fetch_share(
    endpoint: &str,
    request: &AttestRequest,
) -> Result<Option<([u8; bls::SIG_BYTES], [u8; bls::PUBKEY_BYTES])>, RollupProofError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(endpoint)
        .json(request)
        .send()
        .await
        .map_err(|e| err(&format!("calling committee member at {endpoint}"), e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(RollupProofError::ParameterError(format!(
            "committee member {endpoint} returned {status}: {body}"
        )));
    }
    let parsed: AttestResponse = resp
        .json()
        .await
        .map_err(|e| err("decoding committee member response", e))?;
    match (parsed.bls_share, parsed.bls_pubkey) {
        (Some(s), Some(p)) => Ok(Some((parse_share(&s)?, parse_pubkey(&p)?))),
        _ => Ok(None),
    }
}

/// Fan out to the ordered committee members, collect `>= threshold` BLS shares,
/// and aggregate them into a single signature + signer bitmap. Fail-closed: if
/// fewer than `threshold` members vouch, no proof is produced.
async fn obtain_committee(
    members: &[configuration::settings::CommitteeMember],
    threshold: usize,
    blob: &[u8],
    public_inputs: &[[u8; 32]; 4],
    verification: &ForwardedVerification,
) -> Result<AttestationOutcome, RollupProofError> {
    let request = build_attest_request(blob, public_inputs, verification);
    let mut collected: Vec<(usize, [u8; bls::SIG_BYTES])> = Vec::new();

    for (idx, member) in members.iter().enumerate() {
        if member.url.trim().is_empty() {
            continue;
        }
        let endpoint = format!("{}/attest", member.url.trim().trim_end_matches('/'));
        match fetch_share(&endpoint, &request).await {
            Ok(Some((share, pubkey))) => {
                // Defence in depth: a member must return the pubkey it is
                // registered under on-chain at this bitmap index.
                if !member.pubkey.trim().is_empty() {
                    match parse_pubkey(&member.pubkey) {
                        Ok(expected) if expected != pubkey => {
                            warn!(
                                "[attestor_client] committee member {idx} returned a pubkey \
                                 that does not match its configured key; skipping"
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!("[attestor_client] bad configured pubkey for member {idx}: {e}");
                            continue;
                        }
                        _ => {}
                    }
                }
                collected.push((idx, share));
                if collected.len() >= threshold {
                    break;
                }
            }
            Ok(None) => warn!("[attestor_client] committee member {idx} returned no BLS share"),
            Err(e) => warn!("[attestor_client] committee member {idx} failed: {e}"),
        }
    }

    let (sigma, bitmap) = assemble_committee_signature(&collected, threshold)?;
    info!(
        "[attestor_client] Aggregated {} of {} committee shares (threshold {})",
        collected.len(),
        members.len(),
        threshold
    );
    Ok(AttestationOutcome::Committee { sigma, bitmap })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib::proving::nova_v1::bls::SecretKey;

    #[test]
    fn assemble_aggregates_and_builds_bitmap() {
        // Three committee members; signers {0, 2} produce shares over a digest.
        let sks: Vec<SecretKey> = (0u8..3)
            .map(|i| SecretKey::from_ikm(&[0x10 + i; 32]).unwrap())
            .collect();
        let digest = [0x42u8; 32];
        let shares = vec![
            (0usize, sks[0].sign(&digest)),
            (2usize, sks[2].sign(&digest)),
        ];

        let (sigma, bitmap) = assemble_committee_signature(&shares, 2).unwrap();

        // Bitmap bits 0 and 2 set => last byte == 0b101 == 0x05.
        assert_eq!(bitmap[31], 0x05);
        assert!(bitmap[..31].iter().all(|b| *b == 0));

        // The aggregate verifies against the aggregate of signers {0, 2}.
        let apk = bls::aggregate_public_keys(&[sks[0].public_key(), sks[2].public_key()]).unwrap();
        assert!(bls::verify_aggregate(&apk, &digest, &sigma).unwrap());
    }

    #[test]
    fn assemble_fails_below_threshold() {
        let sk = SecretKey::from_ikm(&[0x11u8; 32]).unwrap();
        let shares = vec![(0usize, sk.sign(&[0x42u8; 32]))];
        assert!(assemble_committee_signature(&shares, 2).is_err());
    }
}
