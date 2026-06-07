//! Nova attestation: canonical signing envelope shared by the proposer
//! (attestation *client*) and the standalone attestation *service*
//! (`nightfall_attestor`).
//!
//! The on-chain `NovaRollupVerifier` is a fail-closed gate: it accepts a
//! Nova block proof only if it carries a valid ECDSA signature from a
//! configured attestor over a canonical preimage. This module is the
//! single source of truth for that preimage so the off-chain signer and
//! the on-chain verifier never drift.
//!
//! The preimage is byte-for-byte identical to the `abi.encodePacked`
//! input of `NovaRollupVerifier._attestPreimage`:
//!
//! ```text
//! ATTEST_DOMAIN || chainid (u256) || verifier (address) ||
//! snark_proof || commitments_root (bytes32) ||
//! nullifiers_root (bytes32) || historic_root_root (bytes32) ||
//! transaction_count (u64) || publicInputs[0..4] (u256 each)
//! ```
//!
//! The attestor signs the EIP-191 (`toEthSignedMessageHash`) digest of
//! `keccak256(preimage)`, producing a 65-byte `(r || s || v)` signature
//! with `v ∈ {27, 28}` (the encoding OpenZeppelin `ECDSA` expects).

use crate::proving::nova_v1::proof::NovaProof;
use alloy::primitives::{keccak256, Address};
use std::fmt;

/// Domain separator for the Nova attestation preimage. **MUST** match
/// `ATTEST_DOMAIN` in
/// `blockchain_assets/contracts/proof_verification/nova_v1/NovaRollupVerifier.sol`.
/// Bumping one without the other invalidates every attestation.
pub const ATTEST_DOMAIN: &[u8] = b"NF4_NOVA_ATTEST_V1";

/// Maximum number of IVC steps the verifier accepts. **MUST** match
/// `MAX_STEPS` in `NovaRollupVerifier.sol` and
/// `NovaRollupEngine::DEFAULT_MAX_STEPS`.
pub const MAX_STEPS: u64 = 10_000;

/// Number of public inputs the Nova verifier consumes
/// (`[commitments_root, nullifiers_root, historic_root_root, block_len]`).
pub const NUM_PUBLIC_INPUTS: usize = 4;

/// Length of an ECDSA signature `(r || s || v)`, in bytes.
pub const SIG_BYTES: usize = 65;

/// Errors raised while building, signing, or checking a Nova attestation.
#[derive(Debug)]
pub enum AttestationError {
    /// A 32-byte root field had the wrong length.
    BadRootLength { field: &'static str, len: usize },
    /// The proof's structural preconditions (the necessary conditions
    /// the on-chain verifier also enforces) did not hold.
    StructuralCheck(String),
    /// The attestor key could not be parsed.
    BadKey(String),
    /// Signing failed.
    Signing(String),
    /// Signature recovery failed.
    Recovery(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRootLength { field, len } => {
                write!(f, "{field} is not 32 bytes (got {len})")
            }
            Self::StructuralCheck(m) => write!(f, "structural check failed: {m}"),
            Self::BadKey(m) => write!(f, "invalid attestor key: {m}"),
            Self::Signing(m) => write!(f, "attestor signing failed: {m}"),
            Self::Recovery(m) => write!(f, "signature recovery failed: {m}"),
        }
    }
}

impl std::error::Error for AttestationError {}

fn to_word(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], AttestationError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| AttestationError::BadRootLength {
        field,
        len: bytes.len(),
    })
}

/// Build the canonical attestation preimage from raw fields. Each root
/// and every `public_inputs` entry is a 32-byte big-endian word.
pub fn attestation_preimage(
    chain_id: u64,
    verifier: Address,
    snark_proof: &[u8],
    commitments_root: &[u8; 32],
    nullifiers_root: &[u8; 32],
    historic_root_root: &[u8; 32],
    transaction_count: u64,
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> Vec<u8> {
    let mut pre = Vec::with_capacity(
        ATTEST_DOMAIN.len() + 32 + 20 + snark_proof.len() + 32 * 3 + 8 + 32 * NUM_PUBLIC_INPUTS,
    );
    pre.extend_from_slice(ATTEST_DOMAIN);
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..].copy_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(&chain_id_word);
    pre.extend_from_slice(verifier.as_slice());
    pre.extend_from_slice(snark_proof);
    pre.extend_from_slice(commitments_root);
    pre.extend_from_slice(nullifiers_root);
    pre.extend_from_slice(historic_root_root);
    pre.extend_from_slice(&transaction_count.to_be_bytes());
    for word in public_inputs {
        pre.extend_from_slice(word);
    }
    pre
}

/// Build the canonical preimage from a (root-rewritten, on-chain)
/// [`NovaProof`] and the on-chain public inputs. The proof's roots must
/// be 32 bytes each (big-endian), matching what the contract reads from
/// the bincode blob.
pub fn preimage_from_proof(
    chain_id: u64,
    verifier: Address,
    proof: &NovaProof,
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> Result<Vec<u8>, AttestationError> {
    let commitments_root = to_word("commitments_root", &proof.commitments_root)?;
    let nullifiers_root = to_word("nullifiers_root", &proof.nullifiers_root)?;
    let historic_root_root = to_word("historic_root_root", &proof.historic_root_root)?;
    Ok(attestation_preimage(
        chain_id,
        verifier,
        &proof.snark_proof,
        &commitments_root,
        &nullifiers_root,
        &historic_root_root,
        proof.transaction_count as u64,
        public_inputs,
    ))
}

/// Enforce the **structural preconditions** the on-chain verifier also
/// checks (necessary, not sufficient): the proof's three roots equal
/// `publicInputs[0..2]`, the inner `snark_proof` is at least 64 bytes,
/// and `transaction_count <= MAX_STEPS`. An attestor that co-signs a
/// proof MUST at minimum enforce these so it never vouches for a proof
/// the contract would structurally reject.
pub fn check_structural_binding(
    proof: &NovaProof,
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> Result<(), AttestationError> {
    if proof.snark_proof.len() < 64 {
        return Err(AttestationError::StructuralCheck(format!(
            "snark_proof too short ({} < 64)",
            proof.snark_proof.len()
        )));
    }
    let commitments_root = to_word("commitments_root", &proof.commitments_root)?;
    let nullifiers_root = to_word("nullifiers_root", &proof.nullifiers_root)?;
    let historic_root_root = to_word("historic_root_root", &proof.historic_root_root)?;
    if commitments_root != public_inputs[0] {
        return Err(AttestationError::StructuralCheck(
            "commitments_root != publicInputs[0]".into(),
        ));
    }
    if nullifiers_root != public_inputs[1] {
        return Err(AttestationError::StructuralCheck(
            "nullifiers_root != publicInputs[1]".into(),
        ));
    }
    if historic_root_root != public_inputs[2] {
        return Err(AttestationError::StructuralCheck(
            "historic_root_root != publicInputs[2]".into(),
        ));
    }
    if proof.transaction_count as u64 > MAX_STEPS {
        return Err(AttestationError::StructuralCheck(format!(
            "transaction_count {} > MAX_STEPS {}",
            proof.transaction_count, MAX_STEPS
        )));
    }
    Ok(())
}

/// Sign an attestation `preimage` with the hex-encoded ECDSA
/// `attestor_key`, returning the 65-byte `(r || s || v)` signature
/// (`v ∈ {27, 28}`) over the EIP-191 digest of `keccak256(preimage)`.
pub fn sign_attestation(
    attestor_key: &str,
    preimage: &[u8],
) -> Result<[u8; SIG_BYTES], AttestationError> {
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    let signer: PrivateKeySigner = attestor_key
        .trim()
        .parse()
        .map_err(|e| AttestationError::BadKey(format!("{e}")))?;
    let digest = keccak256(preimage);
    // `sign_message_sync` applies the EIP-191 prefix to the 32-byte
    // digest, matching `MessageHashUtils.toEthSignedMessageHash`.
    let signature = signer
        .sign_message_sync(digest.as_slice())
        .map_err(|e| AttestationError::Signing(format!("{e}")))?;
    Ok(signature.as_bytes())
}

/// Recover the signer address from an attestation `preimage` and its
/// 65-byte signature, exactly as the on-chain `ECDSA.tryRecover` does.
pub fn recover_attestor(
    preimage: &[u8],
    signature: &[u8; SIG_BYTES],
) -> Result<Address, AttestationError> {
    let digest = keccak256(preimage);
    let eip191 = alloy::primitives::eip191_hash_message(digest.as_slice());
    let sig = alloy::primitives::Signature::try_from(&signature[..])
        .map_err(|e| AttestationError::Recovery(format!("{e}")))?;
    sig.recover_address_from_prehash(&eip191)
        .map_err(|e| AttestationError::Recovery(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_proof(snark_len: usize) -> NovaProof {
        NovaProof {
            snark_proof: vec![7u8; snark_len],
            commitments_root: vec![0x11u8; 32],
            nullifiers_root: vec![0x22u8; 32],
            historic_root_root: vec![0x33u8; 32],
            transaction_count: 20,
        }
    }

    fn public_inputs_for(proof: &NovaProof, block_len: u64) -> [[u8; 32]; 4] {
        let mut block_len_word = [0u8; 32];
        block_len_word[24..].copy_from_slice(&block_len.to_be_bytes());
        [
            proof.commitments_root.clone().try_into().unwrap(),
            proof.nullifiers_root.clone().try_into().unwrap(),
            proof.historic_root_root.clone().try_into().unwrap(),
            block_len_word,
        ]
    }

    #[test]
    fn signature_round_trips_and_matches_wire_format() {
        use alloy::signers::local::PrivateKeySigner;

        // Anvil account #8 (the configured dev attestor key).
        let attestor_key = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
        let signer: PrivateKeySigner = attestor_key.parse().unwrap();
        let expected = signer.address();

        let proof = synth_proof(96);
        let pi = public_inputs_for(&proof, 64);
        let preimage =
            preimage_from_proof(31337, Address::from([0xABu8; 20]), &proof, &pi).unwrap();

        let sig = sign_attestation(attestor_key, &preimage).unwrap();
        assert_eq!(sig.len(), 65);
        assert!(sig[64] == 27 || sig[64] == 28, "v byte must be 27 or 28");

        let recovered = recover_attestor(&preimage, &sig).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn preimage_layout_is_packed_and_matches_cast_keccak() {
        let snark_proof = vec![0xAAu8; 5];
        let commitments_root = [0x01u8; 32];
        let nullifiers_root = [0x02u8; 32];
        let historic_root_root = [0x03u8; 32];
        let verifier = Address::from([0x44u8; 20]);
        let pi = [
            commitments_root,
            nullifiers_root,
            historic_root_root,
            [0x05u8; 32],
        ];

        let preimage = attestation_preimage(
            31337,
            verifier,
            &snark_proof,
            &commitments_root,
            &nullifiers_root,
            &historic_root_root,
            9,
            &pi,
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(b"NF4_NOVA_ATTEST_V1");
        let mut chain_word = [0u8; 32];
        chain_word[24..].copy_from_slice(&31337u64.to_be_bytes());
        expected.extend_from_slice(&chain_word);
        expected.extend_from_slice(verifier.as_slice());
        expected.extend_from_slice(&snark_proof);
        expected.extend_from_slice(&commitments_root);
        expected.extend_from_slice(&nullifiers_root);
        expected.extend_from_slice(&historic_root_root);
        expected.extend_from_slice(&9u64.to_be_bytes());
        for word in &pi {
            expected.extend_from_slice(word);
        }
        assert_eq!(preimage, expected);
        assert_eq!(preimage.len(), 18 + 32 + 20 + 5 + 96 + 8 + 128);

        // Cross-tool pin: keccak256 independently computed via Foundry
        // `cast keccak` (same EVM toolchain the verifier uses).
        let digest = keccak256(&preimage);
        assert_eq!(
            hex::encode(digest),
            "3a9bd3476230f99a7711ad50800a5c6998013ab8eeed16076ee9bbe80b0887e8"
        );
    }

    #[test]
    fn structural_binding_accepts_consistent_proof_and_rejects_tampering() {
        let proof = synth_proof(64);
        let pi = public_inputs_for(&proof, 64);
        assert!(check_structural_binding(&proof, &pi).is_ok());

        // Short snark_proof is rejected.
        let short = synth_proof(32);
        let short_pi = public_inputs_for(&short, 64);
        assert!(check_structural_binding(&short, &short_pi).is_err());

        // Tampered public input root is rejected.
        let mut bad_pi = pi;
        bad_pi[0][0] ^= 0xff;
        assert!(check_structural_binding(&proof, &bad_pi).is_err());
    }
}
