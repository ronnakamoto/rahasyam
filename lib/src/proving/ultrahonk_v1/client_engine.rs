use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fmt, fs, io,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::nf_client_proof::{PrivateInputs, ProvingEngine, PublicInputs};

use super::{proof::UltraHonkProof, witness};

const SIDECAR_CIRCUIT_FILE: &str = "nightfish_honk_client_tx.json";
const EXPECTED_CIRCUIT_BYTECODE_SHA256: &str =
    "aa844f9aa7115f9065098733296c48fb4c142ae534e667de2c31989d3eda0db5";

#[derive(Debug)]
pub struct UltraHonkClientEngine;

#[derive(Debug)]
pub enum UltraHonkError {
    MissingSidecar {
        path: PathBuf,
        detail: String,
    },
    Io(io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    InvalidHex(String),
    InvalidFieldElement(String),
    InvalidSidecarCircuit {
        path: PathBuf,
        detail: String,
    },
    CircuitBytecodeHashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    SidecarFailed {
        script: &'static str,
        status: String,
        stderr: String,
    },
    PublicInputMismatch {
        expected: usize,
        actual: usize,
        diffs: Vec<(usize, String, String)>,
    },
    CommittedInputMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    MalformedPublicInputs {
        detail: String,
    },
    Witness(witness::WitnessError),
}

impl fmt::Display for UltraHonkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UltraHonkError::MissingSidecar { path, detail } => {
                write!(
                    f,
                    "UltraHonk sidecar missing at {}: {detail}",
                    path.display()
                )
            }
            UltraHonkError::Io(e) => write!(f, "UltraHonk sidecar I/O failed: {e}"),
            UltraHonkError::Json(e) => write!(f, "UltraHonk sidecar JSON failed: {e}"),
            UltraHonkError::Hex(e) => write!(f, "UltraHonk sidecar hex failed: {e}"),
            UltraHonkError::InvalidHex(value) => write!(f, "invalid hex string: {value}"),
            UltraHonkError::InvalidFieldElement(value) => {
                write!(f, "invalid field element from sidecar: {value}")
            }
            UltraHonkError::InvalidSidecarCircuit { path, detail } => write!(
                f,
                "invalid UltraHonk sidecar circuit at {}: {detail}",
                path.display()
            ),
            UltraHonkError::CircuitBytecodeHashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "UltraHonk sidecar circuit bytecode hash mismatch at {}: expected {expected}, got {actual}",
                path.display()
            ),
            UltraHonkError::SidecarFailed {
                script,
                status,
                stderr,
            } => write!(
                f,
                "UltraHonk sidecar {script} failed with {status}: {stderr}"
            ),
            UltraHonkError::PublicInputMismatch {
                expected,
                actual,
                diffs,
            } => {
                write!(
                    f,
                    "UltraHonk public input mismatch: nf4 expected {expected} words, sidecar circuit returned {actual} words"
                )?;
                for (idx, exp, got) in diffs {
                    write!(f, "; [{idx}] expected={exp} circuit={got}")?;
                }
                Ok(())
            }
            UltraHonkError::CommittedInputMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "UltraHonk circuit changed committed public input `{field}`: client committed {expected} but circuit returned {actual}"
            ),
            UltraHonkError::MalformedPublicInputs { detail } => {
                write!(
                    f,
                    "UltraHonk circuit returned malformed public inputs: {detail}"
                )
            }
            UltraHonkError::Witness(e) => write!(f, "UltraHonk witness generation failed: {e}"),
        }
    }
}

impl std::error::Error for UltraHonkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UltraHonkError::Io(e) => Some(e),
            UltraHonkError::Json(e) => Some(e),
            UltraHonkError::Hex(e) => Some(e),
            UltraHonkError::Witness(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for UltraHonkError {
    fn from(value: io::Error) -> Self {
        UltraHonkError::Io(value)
    }
}

impl From<serde_json::Error> for UltraHonkError {
    fn from(value: serde_json::Error) -> Self {
        UltraHonkError::Json(value)
    }
}

impl From<hex::FromHexError> for UltraHonkError {
    fn from(value: hex::FromHexError) -> Self {
        UltraHonkError::Hex(value)
    }
}

impl From<witness::WitnessError> for UltraHonkError {
    fn from(value: witness::WitnessError) -> Self {
        UltraHonkError::Witness(value)
    }
}

impl ProvingEngine<UltraHonkProof> for UltraHonkClientEngine {
    type Error = UltraHonkError;

    fn prove(
        private_inputs: &mut PrivateInputs,
        public_inputs: &mut PublicInputs,
    ) -> Result<UltraHonkProof, Self::Error> {
        let statement = witness::build_statement_inputs_json(private_inputs, public_inputs)?;
        let output = run_sidecar("prove.mjs", &statement)?;
        if !output.status.success() {
            return Err(sidecar_failed("prove.mjs", &output));
        }

        let response: ProveResponse = serde_json::from_slice(&output.stdout)?;
        let proof = decode_hex(&response.proof_hex)?;
        let returned_public_inputs = response
            .public_inputs
            .iter()
            .map(parse_fr_value)
            .collect::<Result<Vec<_>, _>>()?;

        // The Noir client circuit recomputes the full public-input set from the
        // private witness and returns it as the framed 27-word vector. This is
        // the source of truth, exactly as the PLONK path treats the value
        // returned by `assess_operation_integrity`. The caller passes
        // `public_inputs` with only `fee` and `root` populated and relies on
        // `prove` to write the computed commitments / nullifiers /
        // compressed_secrets / swap fields back (the on-chain ClientTransaction
        // is built from them). Parse the framed vector and populate them here.
        //
        // `fee` and `root` are inputs the client committed to; the circuit must
        // echo them unchanged. Any divergence is a soundness failure, so we
        // fail closed rather than silently trusting the circuit's value.
        let committed_fee = public_inputs.fee;
        let committed_root = public_inputs.root;
        unframe_public_inputs_into(&returned_public_inputs, public_inputs)?;

        if public_inputs.fee != committed_fee {
            return Err(UltraHonkError::CommittedInputMismatch {
                field: "fee",
                expected: fr_to_hex(&committed_fee),
                actual: fr_to_hex(&public_inputs.fee),
            });
        }
        if public_inputs.root != committed_root {
            return Err(UltraHonkError::CommittedInputMismatch {
                field: "root",
                expected: fr_to_hex(&committed_root),
                actual: fr_to_hex(&public_inputs.root),
            });
        }

        // Re-frame the parsed fields and require an exact match with the vector
        // the circuit returned. This validates the framing constant, length
        // separators and our parsing offsets in one shot (fail closed on drift).
        let reframed = Vec::<Fr254>::from(&*public_inputs);
        if reframed != returned_public_inputs {
            let diffs = reframed
                .iter()
                .zip(returned_public_inputs.iter())
                .enumerate()
                .filter(|(_, (e, a))| e != a)
                .take(8)
                .map(|(i, (e, a))| (i, fr_to_hex(e), fr_to_hex(a)))
                .collect::<Vec<_>>();
            return Err(UltraHonkError::PublicInputMismatch {
                expected: reframed.len(),
                actual: returned_public_inputs.len(),
                diffs,
            });
        }

        Ok(UltraHonkProof {
            proof,
            public_inputs: returned_public_inputs,
        })
    }

    fn verify(proof: &UltraHonkProof, public_inputs: &PublicInputs) -> Result<bool, Self::Error> {
        let public_inputs_hex = Vec::<Fr254>::from(public_inputs)
            .iter()
            .map(fr_to_hex)
            .collect::<Vec<_>>();
        let request = json!({
            "proofHex": format!("0x{}", hex::encode(&proof.proof)),
            "publicInputs": public_inputs_hex,
        });
        let output = run_sidecar("verify.mjs", &request)?;

        match serde_json::from_slice::<VerifyResponse>(&output.stdout) {
            Ok(response) => Ok(output.status.success() && response.valid),
            Err(e) if output.status.success() => Err(UltraHonkError::Json(e)),
            Err(_) => Err(sidecar_failed("verify.mjs", &output)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProveResponse {
    #[serde(rename = "proofHex")]
    proof_hex: String,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    valid: bool,
}

fn run_sidecar(
    script: &'static str,
    input: &Value,
) -> Result<std::process::Output, UltraHonkError> {
    let (sidecar_dir, script_path) = sidecar_script(script)?;
    let node_bin = env::var("NODE_BIN").unwrap_or_else(|_| "node".to_string());
    let input = serde_json::to_vec(input)?;

    let mut child = Command::new(node_bin)
        .arg(
            script_path
                .file_name()
                .ok_or_else(|| UltraHonkError::MissingSidecar {
                    path: script_path.clone(),
                    detail: "script path has no file name".to_string(),
                })?,
        )
        .current_dir(sidecar_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "sidecar stdin unavailable"))?
        .write_all(&input)?;

    Ok(child.wait_with_output()?)
}

fn sidecar_script(script: &'static str) -> Result<(PathBuf, PathBuf), UltraHonkError> {
    let sidecar_dir = env::var_os("ULTRAHONK_SIDECAR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_sidecar_dir);
    if !sidecar_dir.is_dir() {
        return Err(UltraHonkError::MissingSidecar {
            path: sidecar_dir,
            detail: "directory does not exist".to_string(),
        });
    }

    ensure_pinned_sidecar_circuit(&sidecar_dir)?;

    let script_path = sidecar_dir.join(script);
    if !script_path.is_file() {
        return Err(UltraHonkError::MissingSidecar {
            path: script_path,
            detail: "script file does not exist".to_string(),
        });
    }

    Ok((sidecar_dir, script_path))
}

fn ensure_pinned_sidecar_circuit(sidecar_dir: &Path) -> Result<(), UltraHonkError> {
    let circuit_path = sidecar_dir.join(SIDECAR_CIRCUIT_FILE);
    if !circuit_path.is_file() {
        return Err(UltraHonkError::MissingSidecar {
            path: circuit_path,
            detail: "circuit file does not exist".to_string(),
        });
    }

    let circuit: Value = serde_json::from_str(&fs::read_to_string(&circuit_path)?)?;
    let bytecode = circuit
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| UltraHonkError::InvalidSidecarCircuit {
            path: circuit_path.clone(),
            detail: "missing string field `bytecode`".to_string(),
        })?;
    let actual = sha256_hex(bytecode.as_bytes());
    if actual != EXPECTED_CIRCUIT_BYTECODE_SHA256 {
        return Err(UltraHonkError::CircuitBytecodeHashMismatch {
            path: circuit_path,
            expected: EXPECTED_CIRCUIT_BYTECODE_SHA256.to_string(),
            actual,
        });
    }

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn default_sidecar_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|repo_root| repo_root.join("ultrahonk_sidecar"))
        .unwrap_or_else(|| PathBuf::from("ultrahonk_sidecar"))
}

fn sidecar_failed(script: &'static str, output: &std::process::Output) -> UltraHonkError {
    UltraHonkError::SidecarFailed {
        script,
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, UltraHonkError> {
    let trimmed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if trimmed.len() % 2 != 0 {
        return Err(UltraHonkError::InvalidHex(value.to_string()));
    }
    Ok(hex::decode(trimmed)?)
}

fn parse_fr_value(value: &Value) -> Result<Fr254, UltraHonkError> {
    match value {
        Value::String(s) => parse_fr_str(s),
        Value::Number(n) => parse_fr_str(&n.to_string()),
        _ => Err(UltraHonkError::InvalidFieldElement(value.to_string())),
    }
}

fn parse_fr_str(value: &str) -> Result<Fr254, UltraHonkError> {
    let trimmed = value.trim();
    let (digits, radix) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .map(|s| (s, 16))
        .unwrap_or((trimmed, 10));
    let bigint = BigUint::parse_bytes(digits.as_bytes(), radix)
        .ok_or_else(|| UltraHonkError::InvalidFieldElement(value.to_string()))?;
    Ok(Fr254::from(bigint))
}

fn fr_to_hex(value: &Fr254) -> String {
    let hex = hex::encode(value.into_bigint().to_bytes_be());
    format!("0x{hex:0>64}")
}

/// Parse the framed 27-word public-input vector the client circuit returns and
/// write the recomputed fields back into `public_inputs`. The layout mirrors
/// `impl From<&PublicInputs> for Vec<Fr254>` in `nf_client_proof.rs`:
///
/// `[framing, 1, fee, 1, root, 4, commitments[4], 4, nullifiers[4], 5,
///   compressed_secrets[5], 1, swap_link, 1, deadline, 1, swap_side]`
///
/// The length separators (`1`/`4`/`4`/`5`/`1`/`1`/`1`) are validated fail-closed
/// so any structural drift between the circuit and the Rust framing is caught.
fn unframe_public_inputs_into(
    framed: &[Fr254],
    public_inputs: &mut PublicInputs,
) -> Result<(), UltraHonkError> {
    const EXPECTED_LEN: usize = 27;
    if framed.len() != EXPECTED_LEN {
        return Err(UltraHonkError::MalformedPublicInputs {
            detail: format!("expected {EXPECTED_LEN} words, got {}", framed.len()),
        });
    }

    let expect_separator = |idx: usize, want: u64| -> Result<(), UltraHonkError> {
        if framed[idx] != Fr254::from(want) {
            return Err(UltraHonkError::MalformedPublicInputs {
                detail: format!(
                    "expected length separator {want} at index {idx}, got {}",
                    fr_to_hex(&framed[idx])
                ),
            });
        }
        Ok(())
    };
    expect_separator(1, 1)?;
    expect_separator(3, 1)?;
    expect_separator(5, 4)?;
    expect_separator(10, 4)?;
    expect_separator(15, 5)?;
    expect_separator(21, 1)?;
    expect_separator(23, 1)?;
    expect_separator(25, 1)?;

    public_inputs.fee = framed[2];
    public_inputs.root = framed[4];
    public_inputs.commitments.copy_from_slice(&framed[6..10]);
    public_inputs.nullifiers.copy_from_slice(&framed[11..15]);
    public_inputs
        .compressed_secrets
        .copy_from_slice(&framed[16..21]);
    public_inputs.swap_link = framed[22];
    public_inputs.deadline = framed[24];
    public_inputs.swap_side = framed[26];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{One, Zero};
    use std::{fs, path::Path};

    #[test]
    fn parses_sidecar_field_elements() {
        assert_eq!(parse_fr_str("0x0").unwrap(), Fr254::zero());
        assert_eq!(parse_fr_str("1").unwrap(), Fr254::one());
    }

    #[test]
    fn formats_public_inputs_as_padded_hex() {
        assert_eq!(
            fr_to_hex(&Fr254::one()),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn pinned_sidecar_circuit_hash_matches_checked_in_bytecode() {
        let sidecar_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("lib crate must be inside workspace")
            .join("ultrahonk_sidecar");
        let circuit_path = sidecar_dir.join(SIDECAR_CIRCUIT_FILE);
        let circuit: Value =
            serde_json::from_str(&fs::read_to_string(circuit_path).unwrap()).unwrap();
        let bytecode = circuit["bytecode"].as_str().unwrap();
        assert_eq!(
            sha256_hex(bytecode.as_bytes()),
            EXPECTED_CIRCUIT_BYTECODE_SHA256
        );
    }

    #[test]
    fn unframe_round_trips_and_populates_public_inputs() {
        // Build a fully-populated PublicInputs, frame it the way the circuit
        // would, then confirm unframing into an empty PublicInputs reproduces
        // every field exactly.
        let mut source = PublicInputs::new();
        source.fee = Fr254::from(7u64);
        source.root = Fr254::from(9u64);
        source.commitments = [11, 12, 13, 14].map(Fr254::from);
        source.nullifiers = [21, 22, 23, 24].map(Fr254::from);
        source.compressed_secrets = [31, 32, 33, 34, 35].map(Fr254::from);
        source.swap_link = Fr254::from(41u64);
        source.deadline = Fr254::from(42u64);
        source.swap_side = Fr254::from(1u64);

        let framed = Vec::<Fr254>::from(&source);
        assert_eq!(framed.len(), 27);

        let mut target = PublicInputs::new();
        unframe_public_inputs_into(&framed, &mut target).unwrap();

        assert_eq!(Vec::<Fr254>::from(&target), framed);
        assert_eq!(target.commitments, source.commitments);
        assert_eq!(target.nullifiers, source.nullifiers);
        assert_eq!(target.compressed_secrets, source.compressed_secrets);
        assert_eq!(target.swap_link, source.swap_link);
    }

    #[test]
    fn unframe_rejects_bad_length_separator() {
        let mut source = PublicInputs::new();
        source.fee = Fr254::from(7u64);
        let mut framed = Vec::<Fr254>::from(&source);
        framed[5] = Fr254::from(3u64); // commitments length separator must be 4
        let mut target = PublicInputs::new();
        assert!(matches!(
            unframe_public_inputs_into(&framed, &mut target),
            Err(UltraHonkError::MalformedPublicInputs { .. })
        ));
    }
}
