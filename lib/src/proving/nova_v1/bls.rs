//! Off-chain BLS12-381 signing for the Nova attestor committee (plan B3).
//!
//! This is the Rust counterpart to the on-chain `Bls12381.sol` /
//! `NovaCommitteeVerifier.sol`. Each attestor in the committee runs the sound
//! `NovaRollupEngine::verify_attestation` and, if it accepts, signs the
//! canonical attestation digest (`keccak256` of
//! [`super::attestation::attestation_preimage`]) with its BLS key. The proposer
//! collects `>= t` shares and aggregates them; the aggregate is verified
//! on-chain with a single EIP-2537 pairing check.
//!
//! Scheme: **min-pubkey** BLS (public keys in G1, signatures in G2),
//! ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, with
//! proof-of-possession registration to defend against rogue-key attacks.
//!
//! All public keys / signatures are encoded exactly as the on-chain verifier
//! expects (EIP-2537: Fp = 64-byte big-endian with the top 16 bytes zero; Fp2
//! = `c0 || c1`; G1 = `x || y` (128 bytes); G2 = `x || y` (256 bytes)), so the
//! bytes produced here are accepted byte-for-byte by the Solidity verifier.

use blst::*;
use std::ptr;

/// Signature-scheme domain separation tag. MUST match `SIG_DST` in
/// `NovaCommitteeVerifier.sol`.
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Proof-of-possession domain separation tag. MUST match `POP_DST` in
/// `NovaCommitteeVerifier.sol`.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// EIP-2537 encoded G1 public key length.
pub const PUBKEY_BYTES: usize = 128;
/// EIP-2537 encoded G2 signature length.
pub const SIG_BYTES: usize = 256;

/// Errors raised while signing, aggregating, or verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// IKM passed to key generation was shorter than 32 bytes.
    ShortIkm(usize),
    /// A raw secret-key scalar was not exactly 32 bytes.
    BadScalarLen(usize),
    /// A raw secret-key scalar was not a canonical `Fr` element.
    InvalidScalar,
    /// A public key was not `PUBKEY_BYTES` long.
    BadPubkeyLen(usize),
    /// A signature was not `SIG_BYTES` long.
    BadSigLen(usize),
    /// A decoded point was not a valid element of its prime-order subgroup.
    NotInSubgroup,
    /// An empty slice was passed to an aggregation routine.
    Empty,
}

impl std::fmt::Display for BlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlsError::ShortIkm(n) => write!(f, "BLS IKM too short ({n} < 32)"),
            BlsError::BadScalarLen(n) => write!(f, "BLS secret key must be 32 bytes (got {n})"),
            BlsError::InvalidScalar => write!(f, "BLS secret key is not a canonical Fr scalar"),
            BlsError::BadPubkeyLen(n) => write!(f, "BLS pubkey must be {PUBKEY_BYTES} bytes (got {n})"),
            BlsError::BadSigLen(n) => write!(f, "BLS signature must be {SIG_BYTES} bytes (got {n})"),
            BlsError::NotInSubgroup => write!(f, "BLS point not in the prime-order subgroup"),
            BlsError::Empty => write!(f, "empty input to BLS aggregation"),
        }
    }
}

impl std::error::Error for BlsError {}

// ---------------------------------------------------------------------------
// EIP-2537 encoding (blst point -> bytes)
// ---------------------------------------------------------------------------

fn fp_to_64(fp: &blst_fp) -> [u8; 64] {
    let mut be48 = [0u8; 48];
    unsafe { blst_bendian_from_fp(be48.as_mut_ptr(), fp) };
    let mut out = [0u8; 64];
    out[16..64].copy_from_slice(&be48);
    out
}

fn p1_to_128(p: &blst_p1) -> [u8; 128] {
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, p) };
    let mut out = [0u8; 128];
    out[0..64].copy_from_slice(&fp_to_64(&aff.x));
    out[64..128].copy_from_slice(&fp_to_64(&aff.y));
    out
}

fn p2_to_256(p: &blst_p2) -> [u8; 256] {
    let mut aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut aff, p) };
    let mut out = [0u8; 256];
    out[0..64].copy_from_slice(&fp_to_64(&aff.x.fp[0]));
    out[64..128].copy_from_slice(&fp_to_64(&aff.x.fp[1]));
    out[128..192].copy_from_slice(&fp_to_64(&aff.y.fp[0]));
    out[192..256].copy_from_slice(&fp_to_64(&aff.y.fp[1]));
    out
}

// ---------------------------------------------------------------------------
// EIP-2537 decoding (bytes -> blst point), with subgroup checks
// ---------------------------------------------------------------------------

fn fp_from_64(b: &[u8]) -> blst_fp {
    // Skip the 16-byte zero pad; the canonical value is the low 48 bytes.
    let mut fp = blst_fp::default();
    unsafe { blst_fp_from_bendian(&mut fp, b[16..64].as_ptr()) };
    fp
}

fn p1_from_128(b: &[u8]) -> Result<blst_p1, BlsError> {
    if b.len() != PUBKEY_BYTES {
        return Err(BlsError::BadPubkeyLen(b.len()));
    }
    let aff = blst_p1_affine { x: fp_from_64(&b[0..64]), y: fp_from_64(&b[64..128]) };
    if !unsafe { blst_p1_affine_in_g1(&aff) } {
        return Err(BlsError::NotInSubgroup);
    }
    let mut p = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p, &aff) };
    Ok(p)
}

fn p2_from_256(b: &[u8]) -> Result<blst_p2, BlsError> {
    if b.len() != SIG_BYTES {
        return Err(BlsError::BadSigLen(b.len()));
    }
    let aff = blst_p2_affine {
        x: blst_fp2 { fp: [fp_from_64(&b[0..64]), fp_from_64(&b[64..128])] },
        y: blst_fp2 { fp: [fp_from_64(&b[128..192]), fp_from_64(&b[192..256])] },
    };
    if !unsafe { blst_p2_affine_in_g2(&aff) } {
        return Err(BlsError::NotInSubgroup);
    }
    let mut p = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut p, &aff) };
    Ok(p)
}

fn hash_to_g2(msg: &[u8], dst: &[u8]) -> blst_p2 {
    let mut h = blst_p2::default();
    unsafe {
        blst_hash_to_g2(&mut h, msg.as_ptr(), msg.len(), dst.as_ptr(), dst.len(), ptr::null(), 0)
    };
    h
}

// ---------------------------------------------------------------------------
// Keys, signing, proof-of-possession
// ---------------------------------------------------------------------------

/// A BLS12-381 secret key (an `Fr` scalar). Zeroized on drop by `blst`.
pub struct SecretKey(blst_scalar);

impl SecretKey {
    /// Derive a secret key from input key material (`ikm` must be >= 32 bytes),
    /// per the BLS KeyGen of draft-irtf-cfrg-bls-signature. Use for one-time
    /// committee key generation.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, BlsError> {
        if ikm.len() < 32 {
            return Err(BlsError::ShortIkm(ikm.len()));
        }
        let mut sk = blst_scalar::default();
        unsafe { blst_keygen(&mut sk, ikm.as_ptr(), ikm.len(), ptr::null(), 0) };
        Ok(SecretKey(sk))
    }

    /// Load a secret key from a 32-byte big-endian `Fr` scalar (the form an
    /// attestor node stores in config). Validates the scalar is canonical.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 32 {
            return Err(BlsError::BadScalarLen(bytes.len()));
        }
        let mut sk = blst_scalar::default();
        unsafe { blst_scalar_from_bendian(&mut sk, bytes.as_ptr()) };
        if !unsafe { blst_scalar_fr_check(&sk) } {
            return Err(BlsError::InvalidScalar);
        }
        Ok(SecretKey(sk))
    }

    /// Parse a secret key from a (optionally `0x`-prefixed) hex string.
    pub fn from_hex(s: &str) -> Result<Self, BlsError> {
        let s = s.trim().trim_start_matches("0x");
        let bytes = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| BlsError::InvalidScalar)?;
        Self::from_bytes(&bytes)
    }

    /// The EIP-2537-encoded G1 public key (`sk * G1`).
    pub fn public_key(&self) -> [u8; PUBKEY_BYTES] {
        let mut pk = blst_p1::default();
        unsafe { blst_sk_to_pk_in_g1(&mut pk, &self.0) };
        p1_to_128(&pk)
    }

    /// Export the 32-byte big-endian scalar (for one-time committee keygen
    /// output; handle as a secret).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), &self.0) };
        out
    }

    /// Sign `message` (the 32-byte attestation digest): `sk * H(message)`,
    /// where `H` is RFC 9380 hash-to-G2 under [`SIG_DST`]. Returns the
    /// EIP-2537-encoded G2 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; SIG_BYTES] {
        let h = hash_to_g2(message, SIG_DST);
        let mut sig = blst_p2::default();
        unsafe { blst_sign_pk_in_g1(&mut sig, &h, &self.0) };
        p2_to_256(&sig)
    }

    /// Produce the proof-of-possession `sk * H_pop(pk)` (message = the 128-byte
    /// pubkey encoding, under [`POP_DST`]) used at on-chain registration.
    pub fn proof_of_possession(&self) -> [u8; SIG_BYTES] {
        let pk = self.public_key();
        let h = hash_to_g2(&pk, POP_DST);
        let mut pop = blst_p2::default();
        unsafe { blst_sign_pk_in_g1(&mut pop, &h, &self.0) };
        p2_to_256(&pop)
    }
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/// Aggregate signature shares (G2) into a single EIP-2537-encoded signature.
pub fn aggregate_signatures(shares: &[[u8; SIG_BYTES]]) -> Result<[u8; SIG_BYTES], BlsError> {
    let mut iter = shares.iter();
    let first = iter.next().ok_or(BlsError::Empty)?;
    let mut acc = p2_from_256(first)?;
    for s in iter {
        let p = p2_from_256(s)?;
        let mut sum = blst_p2::default();
        unsafe { blst_p2_add_or_double(&mut sum, &acc, &p) };
        acc = sum;
    }
    Ok(p2_to_256(&acc))
}

/// Aggregate G1 public keys into a single EIP-2537-encoded key (the on-chain
/// verifier reconstructs this from the signer bitmap; provided here for
/// verification and tests).
pub fn aggregate_public_keys(keys: &[[u8; PUBKEY_BYTES]]) -> Result<[u8; PUBKEY_BYTES], BlsError> {
    let mut iter = keys.iter();
    let first = iter.next().ok_or(BlsError::Empty)?;
    let mut acc = p1_from_128(first)?;
    for k in iter {
        let p = p1_from_128(k)?;
        let mut sum = blst_p1::default();
        unsafe { blst_p1_add_or_double(&mut sum, &acc, &p) };
        acc = sum;
    }
    Ok(p1_to_128(&acc))
}

// ---------------------------------------------------------------------------
// Verification (mirrors the on-chain pairing check; for tests / sanity)
// ---------------------------------------------------------------------------

fn neg_g1_affine() -> blst_p1_affine {
    let mut g = unsafe { *blst_p1_generator() };
    unsafe { blst_p1_cneg(&mut g, true) };
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, &g) };
    aff
}

/// Verify an aggregate signature against an aggregate public key and message:
/// `e(-G1, sigma) * e(apk, H(message)) == 1`, identical to the on-chain
/// `NovaCommitteeVerifier.verifyDigest` pairing.
pub fn verify_aggregate(
    apk: &[u8; PUBKEY_BYTES],
    message: &[u8],
    sigma: &[u8; SIG_BYTES],
) -> Result<bool, BlsError> {
    let apk_p = p1_from_128(apk)?;
    let sig_p = p2_from_256(sigma)?;

    let mut apk_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut apk_aff, &apk_p) };
    let mut sig_aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut sig_aff, &sig_p) };

    let h = hash_to_g2(message, SIG_DST);
    let mut h_aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut h_aff, &h) };

    let neg_g1 = neg_g1_affine();

    unsafe {
        let mut ml0 = blst_fp12::default();
        let mut ml1 = blst_fp12::default();
        // e(-G1, sigma)
        blst_miller_loop(&mut ml0, &sig_aff, &neg_g1);
        // e(apk, H(message))
        blst_miller_loop(&mut ml1, &h_aff, &apk_aff);
        let mut prod = blst_fp12::default();
        blst_fp12_mul(&mut prod, &ml0, &ml1);
        let mut gt = blst_fp12::default();
        blst_final_exp(&mut gt, &prod);
        Ok(blst_fp12_is_one(&gt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dehex(s: &str) -> Vec<u8> {
        let s = s.trim().trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Fixed 32-byte stand-in for keccak256(attestation_preimage(..)).
    const MSG_HEX: &str = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89";

    #[test]
    fn sign_aggregate_verify_roundtrip() {
        let sk0 = SecretKey::from_ikm(&[0x11u8; 32]).unwrap();
        let sk1 = SecretKey::from_ikm(&[0x22u8; 32]).unwrap();
        let msg = dehex(MSG_HEX);

        let sig0 = sk0.sign(&msg);
        let sig1 = sk1.sign(&msg);
        let sigma = aggregate_signatures(&[sig0, sig1]).unwrap();
        let apk = aggregate_public_keys(&[sk0.public_key(), sk1.public_key()]).unwrap();

        assert!(verify_aggregate(&apk, &msg, &sigma).unwrap(), "valid aggregate must verify");

        // Wrong message must not verify.
        let mut bad = msg.clone();
        bad[0] ^= 0x01;
        assert!(!verify_aggregate(&apk, &bad, &sigma).unwrap(), "tampered message must fail");
    }

    /// Byte-for-byte parity with the vectors the on-chain
    /// `NovaCommitteeVerifierTest` proves are accepted. If these match, the
    /// off-chain encoding is on-chain-acceptable by transitivity.
    #[test]
    fn encoding_parity_with_onchain_vectors() {
        // Generated by `temp/bls_parity_spike/rustgen` and verified on-chain.
        let expected_pk0 = dehex(
            "000000000000000000000000000000000e5a712e4cb2c51893c27ae19afb3455f3efcc66030dc25e13eb1afc2edf397317a0bb2d28a55513a32d7dcc404be3ba000000000000000000000000000000000584bfddb088df7d913dbe8441e21a556e6b59e630f2f84ad8f4fe8efc15305917ce3a09536a871966a02667709b69d2",
        );
        let expected_sigma = dehex(
            "000000000000000000000000000000000064f51676c4a55677539bee3e32a2859f3d6089d8be1e13fb964374a27a1f0ec31a5f6b9ecacb7e6afed820dae5b1140000000000000000000000000000000015d9074df20ad0967c8aa586a7de1c1811e6d03214a6091f216d56d8d5cf37e4011367d080247b35d4d59f82691f71750000000000000000000000000000000010482d62f2e05e7ab298e1b6b5fb3f1af2193d93a7a63568b8648a48b8595aa99680f5e94334c81460bd5a986500d7f100000000000000000000000000000000130ce06a490a5d44959c1f87af2822151f1c2b709778e37e4728e3a806d02639ad2ae7fd5c9ffd207fa73d3d4767c6c9",
        );

        let sk0 = SecretKey::from_ikm(&[0x11u8; 32]).unwrap();
        let sk1 = SecretKey::from_ikm(&[0x22u8; 32]).unwrap();
        let msg = dehex(MSG_HEX);

        assert_eq!(sk0.public_key().to_vec(), expected_pk0, "pubkey encoding drift vs on-chain");

        let sigma =
            aggregate_signatures(&[sk0.sign(&msg), sk1.sign(&msg)]).unwrap();
        assert_eq!(sigma.to_vec(), expected_sigma, "aggregate signature drift vs on-chain");
    }

    #[test]
    fn proof_of_possession_verifies() {
        let sk = SecretKey::from_ikm(&[0x11u8; 32]).unwrap();
        let pk = sk.public_key();
        let pop = sk.proof_of_possession();
        // PoP is a signature over the pubkey bytes under POP_DST, so verify with
        // a hand-rolled pairing using the POP hash.
        let h = hash_to_g2(&pk, POP_DST);
        let mut h_aff = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut h_aff, &h) };
        let pk_p = p1_from_128(&pk).unwrap();
        let mut pk_aff = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut pk_aff, &pk_p) };
        let sig_p = p2_from_256(&pop).unwrap();
        let mut sig_aff = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut sig_aff, &sig_p) };
        let neg_g1 = neg_g1_affine();
        let ok = unsafe {
            let mut ml0 = blst_fp12::default();
            let mut ml1 = blst_fp12::default();
            blst_miller_loop(&mut ml0, &sig_aff, &neg_g1);
            blst_miller_loop(&mut ml1, &h_aff, &pk_aff);
            let mut prod = blst_fp12::default();
            blst_fp12_mul(&mut prod, &ml0, &ml1);
            let mut gt = blst_fp12::default();
            blst_final_exp(&mut gt, &prod);
            blst_fp12_is_one(&gt)
        };
        assert!(ok, "proof-of-possession must verify");
    }

    #[test]
    fn rejects_short_ikm() {
        assert!(matches!(SecretKey::from_ikm(&[0u8; 16]), Err(BlsError::ShortIkm(16))));
    }

    #[test]
    fn from_bytes_roundtrip_and_matches_ikm_key() {
        let sk = SecretKey::from_ikm(&[0x11u8; 32]).unwrap();
        let bytes = sk.to_bytes();
        // Reload from the raw scalar and confirm identical pubkey + signature.
        let sk2 = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.public_key(), sk2.public_key());
        let msg = dehex(MSG_HEX);
        assert_eq!(sk.sign(&msg), sk2.sign(&msg));
        // Hex loader agrees.
        let sk3 = SecretKey::from_hex(&format!("0x{}", hex_str(&bytes))).unwrap();
        assert_eq!(sk.public_key(), sk3.public_key());
    }

    #[test]
    fn rejects_bad_scalar() {
        assert!(matches!(SecretKey::from_bytes(&[0u8; 16]), Err(BlsError::BadScalarLen(16))));
        // The Fr modulus itself is not a canonical scalar (must be < r).
        let r = dehex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        assert!(matches!(SecretKey::from_bytes(&r), Err(BlsError::InvalidScalar)));
    }

    fn hex_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
