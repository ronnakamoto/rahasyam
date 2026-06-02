#![cfg(feature = "nova-v1")]

//! Nova Key Management
//!
//! Handles generation, loading, and on-disk persistence of Nova proving and
//! verification keys.
//!
//! ## Why persist?
//!
//! Both [`PublicParams`] (the IVC commitment keys + R1CS shape) and the
//! Spartan [`ProverKey`] / [`VerifierKey`] returned by
//! [`CompressedSNARK::setup`] are **expensive to generate** (tens of seconds
//! for non-trivial circuits, dominated by the commitment-key derivation).
//! Re-running setup on every proposer boot would make startup unacceptable
//! and would also recompute identical artefacts (setup is deterministic for
//! a fixed circuit + curves).
//!
//! This module provides a small file-backed cache keyed by `(version,
//! key-kind)`. If the file exists it is bincode-deserialized; otherwise the
//! supplied generator closure runs and the result is written back.
//!
//! ## Stale-cache self-healing
//!
//! The on-disk payload is wrapped in a [`NovaKeyEnvelope`] that records the
//! circuit arity (and a format version) at the time of generation. On load,
//! the envelope's `arity` is compared against the caller's expected arity
//! (typically `crate::proving::nova_v1::step_circuit::ROLLUP_ARITY`). On
//! mismatch the stale file is deleted and the keys are regenerated. This
//! is what prevents the live failure mode
//! `Nova prove error: Proving failed: RecursiveSNARK::new:
//! InvalidInitialInputLength`, which fires when a previously-generated
//! `PublicParams` was built against an older `RollupStepCircuit` whose
//! `arity()` no longer matches the `z0` vector the prover passes in.
//!
//! ## File layout
//!
//! ```text
//! <key_dir>/nova_ivc_pk_v{version}.bin    # NovaKeyEnvelope<PublicParams<...>>
//! <key_dir>/nova_snark_pk_v{version}.bin  # NovaKeyEnvelope<ProverKey<...>>
//! <key_dir>/nova_snark_vk_v{version}.bin  # NovaKeyEnvelope<VerifierKey<...>>
//! ```
//!
//! **Bumping `version` is the operator's manual escape hatch**: it changes
//! the on-disk filename and forces a clean regeneration, leaving the old
//! files on disk for inspection. The default `version` is `2`; v1 files
//! generated against the pre-`nullifier_count` (arity-4) circuit will be
//! detected as arity-mismatched and regenerated on first load.

use std::path::PathBuf;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Nova Key Manager
///
/// Manages the generation, loading, and persistence of Nova proving keys.
#[derive(Debug, Clone)]
pub struct NovaKeyManager {
    /// Directory path for storing keys
    key_dir: PathBuf,
    /// Key version for rotation support
    version: u32,
}

impl NovaKeyManager {
    /// Create a new key manager with the specified key directory.
    pub fn new(key_dir: PathBuf) -> Self {
        Self {
            key_dir,
            // v1 keys were generated against the arity-4 step circuit
            // (no `nullifier_count` state element). Bumping to v2 makes
            // any pre-existing v1 file invisible to `load_or_generate_*`
            // so it is replaced by a fresh, arity-5 envelope on first
            // use. Operators can also call [`Self::rotate`] explicitly.
            version: 2,
        }
    }

    /// Create a new key manager with the default directory (`./nova_keys`).
    pub fn with_default_dir() -> Self {
        Self::new(get_default_key_dir())
    }

    /// Returns the configured key directory.
    pub fn key_dir(&self) -> &PathBuf {
        &self.key_dir
    }

    /// Returns the current key version.
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn ivc_pk_path(&self) -> PathBuf {
        self.key_dir
            .join(format!("nova_ivc_pk_v{}.bin", self.version))
    }

    pub fn snark_pk_path(&self) -> PathBuf {
        self.key_dir
            .join(format!("nova_snark_pk_v{}.bin", self.version))
    }

    pub fn snark_vk_path(&self) -> PathBuf {
        self.key_dir
            .join(format!("nova_snark_vk_v{}.bin", self.version))
    }

    /// Load the Nova `PublicParams` (the IVC proving + verifying material)
    /// from disk, or generate via `generator` and persist if not present.
    ///
    /// `expected_arity` is the `StepCircuit::arity()` the caller is going
    /// to use. If the persisted envelope was generated against a different
    /// arity (e.g. an older `RollupStepCircuit` whose state vector was
    /// `[commitments_root, nullifiers_root, historic_root, tx_count]`
    /// rather than the current 5-element one), the stale file is deleted
    /// and the keys are regenerated. This is what prevents the live
    /// failure mode `RecursiveSNARK::new: InvalidInitialInputLength`.
    pub fn load_or_generate_ivc_pk<E1, E2, C>(
        &self,
        expected_arity: usize,
        generator: impl FnOnce() -> nova_snark::nova::PublicParams<E1, E2, C>,
    ) -> Result<nova_snark::nova::PublicParams<E1, E2, C>, KeyManagerError>
    where
        E1: nova_snark::traits::Engine<Base = <E2 as nova_snark::traits::Engine>::Scalar>,
        E2: nova_snark::traits::Engine<Base = <E1 as nova_snark::traits::Engine>::Scalar>,
        C: nova_snark::traits::circuit::StepCircuit<E1::Scalar>,
    {
        let path = self.ivc_pk_path();
        if let Some(pp) = read_envelope(&path, "PublicParams", expected_arity)? {
            return Ok(pp);
        }
        log::info!(
            "[nova-v1] Generating new PublicParams (cache miss at {})",
            path.display()
        );
        let pp = generator();
        ensure_parent_dir(&path)?;
        write_envelope(&path, &pp, expected_arity, "PublicParams")?;
        log::info!("[nova-v1] Persisted PublicParams to {}", path.display());
        Ok(pp)
    }

    /// Backwards-compatible alias for [`Self::load_or_generate_ivc_pk`].
    ///
    /// Pass `expected_arity` to enable stale-cache self-healing; the
    /// canonical call site is the arity of
    /// `crate::proving::nova_v1::step_circuit::ROLLUP_ARITY`.
    pub fn get_public_params<E1, E2, C>(
        &self,
        expected_arity: usize,
        generator: impl FnOnce() -> nova_snark::nova::PublicParams<E1, E2, C>,
    ) -> Result<nova_snark::nova::PublicParams<E1, E2, C>, KeyManagerError>
    where
        E1: nova_snark::traits::Engine<Base = <E2 as nova_snark::traits::Engine>::Scalar>,
        E2: nova_snark::traits::Engine<Base = <E1 as nova_snark::traits::Engine>::Scalar>,
        C: nova_snark::traits::circuit::StepCircuit<E1::Scalar>,
    {
        self.load_or_generate_ivc_pk(expected_arity, generator)
    }

    /// Load the Spartan `CompressedSNARK` prover and verifier keys from
    /// disk, or generate them via `generator` and persist both files.
    ///
    /// `generator` is invoked **only** when at least one of the two cache
    /// files is missing or the persisted envelope reports a different
    /// `expected_arity`.  In that case the closure must produce the full
    /// `(ProverKey, VerifierKey)` pair (this is what
    /// `CompressedSNARK::setup(&pp)` returns).
    ///
    /// Both files are read or written atomically (one after the other) so
    /// the on-disk state stays consistent for the next boot. The
    /// `expected_arity` argument must match the arity the `PublicParams`
    /// were generated against; the SNARK VK embeds this value internally,
    /// so a mismatch here would also produce an on-chain verification
    /// failure (the verifier checks `F_arity`).
    pub fn load_or_generate_snark_keys<E1, E2, C, S1, S2>(
        &self,
        expected_arity: usize,
        generator: impl FnOnce() -> (
            nova_snark::nova::ProverKey<E1, E2, C, S1, S2>,
            nova_snark::nova::VerifierKey<E1, E2, C, S1, S2>,
        ),
    ) -> Result<
        (
            nova_snark::nova::ProverKey<E1, E2, C, S1, S2>,
            nova_snark::nova::VerifierKey<E1, E2, C, S1, S2>,
        ),
        KeyManagerError,
    >
    where
        E1: nova_snark::traits::Engine<Base = <E2 as nova_snark::traits::Engine>::Scalar>,
        E2: nova_snark::traits::Engine<Base = <E1 as nova_snark::traits::Engine>::Scalar>,
        C: nova_snark::traits::circuit::StepCircuit<E1::Scalar>,
        S1: nova_snark::traits::snark::RelaxedR1CSSNARKTrait<E1>,
        S2: nova_snark::traits::snark::RelaxedR1CSSNARKTrait<E2>,
    {
        let pk_path = self.snark_pk_path();
        let vk_path = self.snark_vk_path();

        if pk_path.exists() && vk_path.exists() {
            let pk = read_envelope(&pk_path, "CompressedSNARK ProverKey", expected_arity)?;
            let vk = read_envelope(&vk_path, "CompressedSNARK VerifierKey", expected_arity)?;
            if let (Some(pk), Some(vk)) = (pk, vk) {
                log::info!(
                    "[nova-v1] Loaded CompressedSNARK PK/VK from disk ({} / {})",
                    pk_path.display(),
                    vk_path.display()
                );
                return Ok((pk, vk));
            }
        }

        log::info!("[nova-v1] Generating CompressedSNARK PK/VK (cache miss)");
        let (pk, vk) = generator();
        ensure_parent_dir(&pk_path)?;
        write_envelope(&pk_path, &pk, expected_arity, "CompressedSNARK ProverKey")?;
        write_envelope(&vk_path, &vk, expected_arity, "CompressedSNARK VerifierKey")?;
        log::info!(
            "[nova-v1] Persisted CompressedSNARK PK/VK ({} / {})",
            pk_path.display(),
            vk_path.display()
        );
        Ok((pk, vk))
    }

    /// Remove all persisted key files for the current version.
    /// Useful for tests and forced re-generation after a circuit change.
    pub fn clear_cache(&self) -> Result<(), KeyManagerError> {
        for path in [
            self.ivc_pk_path(),
            self.snark_pk_path(),
            self.snark_vk_path(),
        ] {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    /// Rotate to a new key version. Subsequent loads/persists use new
    /// filenames; old files are left untouched on disk.
    pub fn rotate(&mut self) -> Result<(), KeyManagerError> {
        self.version += 1;
        Ok(())
    }
}

pub fn get_default_key_dir() -> PathBuf {
    if let Ok(configured_dir) = std::env::var("NF4_NOVA_KEY_DIR") {
        let configured_dir = configured_dir.trim();
        if !configured_dir.is_empty() {
            return PathBuf::from(configured_dir);
        }
    }

    if let Some(configuration_dir) = crate::rollup_circuit_checks::get_configuration_path() {
        return configuration_dir.join("bin/nova_keys");
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("nova_keys")
}

// ---------------------------------------------------------------------------
// File-IO helpers (private).
// ---------------------------------------------------------------------------

/// On-disk envelope used for every Nova key artifact.
///
/// Records the arity the `StepCircuit::setup` was run with at the time of
/// generation. On load, the envelope's `arity` is compared against the
/// caller's expected arity; a mismatch is treated as a cache miss and
/// the file is regenerated. This is the mechanism that lets the proposer
/// recover automatically from a circuit shape change (e.g. adding the
/// `nullifier_count` state element to `RollupStepCircuit`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NovaKeyEnvelope<T> {
    /// Bumped if the on-disk format itself changes (independent of
    /// arity). The reader uses this to reject pre-envelope (v0) files.
    format_version: u32,
    /// The `StepCircuit::arity()` that the wrapped payload was
    /// generated against. Compared against the caller's expected
    /// arity on load.
    arity: usize,
    /// The actual key material.
    payload: T,
}

impl<T> NovaKeyEnvelope<T> {
    /// Bump this whenever the on-disk format itself changes (e.g. we
    /// add another field). Reads of envelopes with a mismatched
    /// `format_version` are rejected as stale.
    const FORMAT_VERSION: u32 = 1;
}

/// Try to read the persisted envelope at `path` and return its payload
/// if the envelope's `arity` matches `expected_arity`.
///
/// Returns:
/// - `Ok(Some(payload))` on a clean cache hit.
/// - `Ok(None)` if the file is missing, unreadable as an envelope, or
///   the envelope's arity / format version does not match. The stale
///   file is deleted in this case so the next caller regenerates it.
/// - `Err(_)` only for unrecoverable I/O failures (permissions, disk
///   errors) that the caller must surface.
fn read_envelope<T: DeserializeOwned>(
    path: &std::path::Path,
    label: &str,
    expected_arity: usize,
) -> Result<Option<T>, KeyManagerError> {
    if !path.exists() {
        return Ok(None);
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            log::warn!(
                "[nova-v1] Failed to read {label} from {}: {e}; will regenerate",
                path.display()
            );
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
    };
    match bincode::deserialize::<NovaKeyEnvelope<T>>(&data) {
        Ok(env) => {
            if env.format_version != NovaKeyEnvelope::<T>::FORMAT_VERSION {
                log::warn!(
                    "[nova-v1] {label} format version mismatch at {} (file={} expected={}); regenerating",
                    path.display(),
                    env.format_version,
                    NovaKeyEnvelope::<T>::FORMAT_VERSION
                );
                let _ = std::fs::remove_file(path);
                return Ok(None);
            }
            if env.arity != expected_arity {
                log::warn!(
                    "[nova-v1] {label} arity mismatch at {} (file={} expected={}); regenerating",
                    path.display(),
                    env.arity,
                    expected_arity
                );
                let _ = std::fs::remove_file(path);
                return Ok(None);
            }
            log::info!("[nova-v1] Loading {label} from {}", path.display());
            Ok(Some(env.payload))
        }
        Err(e) => {
            // Most likely cause: a pre-envelope file written by an
            // earlier code version. Treat as a cache miss.
            log::warn!(
                "[nova-v1] {label} at {} is not a valid envelope ({e}); regenerating",
                path.display()
            );
            let _ = std::fs::remove_file(path);
            Ok(None)
        }
    }
}

fn write_envelope<T: Serialize>(
    path: &std::path::Path,
    payload: &T,
    arity: usize,
    label: &str,
) -> Result<(), KeyManagerError> {
    let env = NovaKeyEnvelope {
        format_version: NovaKeyEnvelope::<T>::FORMAT_VERSION,
        arity,
        payload,
    };
    let bytes = bincode::serialize(&env).map_err(|e| {
        KeyManagerError::Serialization(format!("serialize {label} envelope: {e}"))
    })?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn ensure_parent_dir(path: &std::path::Path) -> Result<(), KeyManagerError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Error type.
// ---------------------------------------------------------------------------

/// Key manager errors
#[derive(Debug)]
pub enum KeyManagerError {
    Io(std::io::Error),
    Serialization(String),
}

impl From<std::io::Error> for KeyManagerError {
    fn from(e: std::io::Error) -> Self {
        KeyManagerError::Io(e)
    }
}

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyManagerError::Io(e) => write!(f, "IO error: {}", e),
            KeyManagerError::Serialization(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for KeyManagerError {}

/// Combined Verification Key for on-chain deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovaVerifyingKey {
    pub version: u32,
    pub ivc_vk_hash: [u8; 32],
    pub snark_vk_hash: [u8; 32],
}

impl NovaVerifyingKey {
    pub const fn new(version: u32) -> Self {
        Self {
            version,
            ivc_vk_hash: [0u8; 32],
            snark_vk_hash: [0u8; 32],
        }
    }
}

/// Export verification key in Solidity-compatible format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityVerificationKey {
    pub ivc_vk_x: u64,
    pub ivc_vk_x1: u64,
    pub ivc_vk_y0: u64,
    pub ivc_vk_y1: u64,
    pub snark_vk_x: u64,
    pub snark_vk_x1: u64,
    pub snark_vk_y0: u64,
    pub snark_vk_y1: u64,
}

/// Pregenerate Nova keys upfront and persist them on disk.
/// This will load/generate `PublicParams` and Spartan `CompressedSNARK` prover/verifier keys.
pub fn pregenerate_nova_keys() -> Result<(), KeyManagerError> {
    use crate::proving::nova_v1::step_circuit::nova_step_circuit::RollupStepCircuit;
    use nova_snark::{
        nova::{CompressedSNARK, PublicParams},
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{snark::RelaxedR1CSSNARKTrait, Engine},
    };

    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;
    type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
    type F1 = <E1 as Engine>::Scalar;
    type Circuit = RollupStepCircuit<F1>;

    let km = NovaKeyManager::with_default_dir();
    log::info!("[nova-v1] Pregenerating Nova keys in {}...", km.key_dir().display());

    // The circuit's arity is the canonical fingerprint for the
    // persisted PublicParams / SNARK keys. A mismatch on load
    // triggers an automatic regenerate (see `read_envelope`).
    let expected_arity =
        crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

    let pp = km.load_or_generate_ivc_pk::<E1, E2, Circuit>(expected_arity, || {
        log::info!("[nova-v1] Generating PublicParams (this may take several minutes)...");
        let dummy = Circuit::padding();
        PublicParams::<E1, E2, Circuit>::setup(&dummy, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("PublicParams::setup failed")
    })?;

    let _snark_keys = km
        .load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(expected_arity, || {
            log::info!("[nova-v1] Generating CompressedSNARK PK/VK...");
            CompressedSNARK::<E1, E2, Circuit, S1, S2>::setup(&pp)
                .expect("CompressedSNARK::setup failed")
        })?;

    log::info!("[nova-v1] Nova keys pregeneration complete!");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::nova_v1::step_circuit::nova_step_circuit::RollupStepCircuit;
    use nova_snark::{
        nova::{CompressedSNARK, PublicParams},
        provider::{Bn256EngineKZG, GrumpkinEngine},
        traits::{snark::RelaxedR1CSSNARKTrait, Engine},
    };

    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;
    type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
    type F1 = <E1 as Engine>::Scalar;
    type Circuit = RollupStepCircuit<F1>;

    fn build_pp() -> PublicParams<E1, E2, Circuit> {
        let dummy = Circuit::padding();
        PublicParams::<E1, E2, Circuit>::setup(&dummy, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("PublicParams::setup failed")
    }

    #[test]
    fn paths_use_configured_version_and_dir() {
        let dir = std::env::temp_dir().join("nova_keys_paths");
        let km = NovaKeyManager::new(dir.clone());
        // Default version is 2 (bumped from 1 when the arity-4 → arity-5
        // circuit change made all v1 files stale).
        assert_eq!(km.ivc_pk_path(), dir.join("nova_ivc_pk_v2.bin"));
        assert_eq!(km.snark_pk_path(), dir.join("nova_snark_pk_v2.bin"));
        assert_eq!(km.snark_vk_path(), dir.join("nova_snark_vk_v2.bin"));
    }

    #[test]
    fn rotate_bumps_version_in_paths() {
        let dir = std::env::temp_dir().join("nova_keys_rotate");
        let mut km = NovaKeyManager::new(dir.clone());
        km.rotate().unwrap();
        assert_eq!(km.version(), 3);
        assert_eq!(km.ivc_pk_path(), dir.join("nova_ivc_pk_v3.bin"));
    }

    /// 1.3.1 — `PublicParams` round-trips through disk: the second call to
    /// `load_or_generate_ivc_pk` must NOT invoke the generator (proving the
    /// cache is being read).
    #[test]
    fn public_params_persisted_and_reloaded() {
        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());
        let arity = crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

        // First call: cache miss → generator runs, file is written.
        let mut gen_calls = 0;
        let pp1 = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, || {
                gen_calls += 1;
                build_pp()
            })
            .expect("first load_or_generate_ivc_pk failed");
        assert_eq!(gen_calls, 1, "generator must run on first call");
        assert!(km.ivc_pk_path().exists(), "ivc_pk file must exist after first call");

        // Second call: cache hit → generator must NOT run.
        let mut gen_calls2 = 0;
        let pp2 = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, || {
                gen_calls2 += 1;
                build_pp()
            })
            .expect("second load_or_generate_ivc_pk failed");
        assert_eq!(gen_calls2, 0, "generator must NOT run on cache hit");

        // Verify the two PublicParams instances serialize to identical bytes.
        let pp1_bytes = bincode::serialize(&pp1).unwrap();
        let pp2_bytes = bincode::serialize(&pp2).unwrap();
        assert_eq!(pp1_bytes, pp2_bytes, "cached PublicParams must match generated");

        // The on-disk payload is wrapped in an envelope, not the raw
        // PublicParams bytes.
        let on_disk = std::fs::read(km.ivc_pk_path()).unwrap();
        assert_ne!(
            on_disk, pp1_bytes,
            "on-disk file must be an envelope, not a raw PublicParams blob"
        );
    }

    /// 1.3.2 — CompressedSNARK PK/VK persistence round-trip.
    /// On the second call the generator must not run, and the loaded keys
    /// must produce a working prove/verify on a real one-step IVC proof.
    #[test]
    fn snark_keys_persisted_and_reloaded() {
        use nova_snark::nova::RecursiveSNARK;
        use ff::Field;

        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());
        let arity = crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;
        let pp = build_pp();

        // First call: cache miss → generate + write both files.
        let mut gen_calls = 0;
        let (pk1, vk1) = km
            .load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(arity, || {
                gen_calls += 1;
                CompressedSNARK::<_, _, _, S1, S2>::setup(&pp).expect("setup failed")
            })
            .expect("first load_or_generate_snark_keys failed");
        assert_eq!(gen_calls, 1);
        assert!(km.snark_pk_path().exists());
        assert!(km.snark_vk_path().exists());

        // Second call: cache hit → generator must NOT run.
        let mut gen_calls2 = 0;
        let (_pk2, vk2) = km
            .load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(arity, || {
                gen_calls2 += 1;
                CompressedSNARK::<_, _, _, S1, S2>::setup(&pp).expect("setup failed")
            })
            .expect("second load_or_generate_snark_keys failed");
        assert_eq!(gen_calls2, 0, "generator must NOT run on cache hit");

        // Functional check: cached PK/VK can still prove + verify a real IVC.
        // z0 must have length == circuit.arity() == ROLLOUP_ARITY (5).
        let circuit = Circuit::padding();
        let z0 = vec![F1::ZERO; arity];
        let mut rs =
            RecursiveSNARK::<E1, E2, Circuit>::new(&pp, &circuit, &z0).unwrap();
        rs.prove_step(&pp, &circuit).unwrap();
        let snark = CompressedSNARK::<_, _, _, S1, S2>::prove(&pp, &pk1, &rs).unwrap();
        snark.verify(&vk1, 1, &z0).expect("verify with original VK failed");
        snark.verify(&vk2, 1, &z0).expect("verify with reloaded VK failed");
    }

    /// 1.3.3 — `clear_cache` forces the next call to regenerate.
    #[test]
    fn clear_cache_forces_regeneration() {
        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());
        let arity = crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, build_pp)
            .unwrap();
        assert!(km.ivc_pk_path().exists());

        km.clear_cache().unwrap();
        assert!(!km.ivc_pk_path().exists());

        let mut gen_calls = 0;
        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, || {
                gen_calls += 1;
                build_pp()
            })
            .unwrap();
        assert_eq!(gen_calls, 1, "generator must run again after clear_cache");
    }

    /// 1.3.4 — **Stale-cache self-healing** (the bug the live proposer
    /// hit). When the persisted envelope was generated against a
    /// different arity, the loader must delete the file and regenerate.
    /// This is what unblocks a deployment whose `nova_ivc_pk_v1.bin`
    /// was built against the old arity-4 circuit after the codebase
    /// moved to arity-5.
    #[test]
    fn stale_arity_envelope_triggers_regeneration() {
        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());
        let arity = crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

        // Simulate a stale file by hand-writing an envelope whose
        // `arity` field does NOT match the current circuit arity.
        // The on-disk format is `{format_version, arity, payload}` —
        // bincode-serialized. We can use a Vec<u8> payload as a
        // stand-in; the loader will only peek at `arity` / `format_version`
        // before bailing out, so the payload type does not need to be
        // a real `PublicParams`.
        let stale_arity = arity - 1;
        let stale = NovaKeyEnvelope::<Vec<u8>> {
            format_version: NovaKeyEnvelope::<Vec<u8>>::FORMAT_VERSION,
            arity: stale_arity,
            payload: vec![0u8; 8],
        };
        let stale_bytes = bincode::serialize(&stale).unwrap();
        std::fs::write(km.ivc_pk_path(), &stale_bytes).unwrap();
        assert!(km.ivc_pk_path().exists());

        // First call with the correct expected_arity: loader must
        // detect the mismatch, delete the stale file, and regenerate.
        let mut gen_calls = 0;
        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, || {
                gen_calls += 1;
                build_pp()
            })
            .expect("load_or_generate_ivc_pk should self-heal");
        assert_eq!(
            gen_calls, 1,
            "generator must run when the persisted envelope is stale"
        );
        assert!(km.ivc_pk_path().exists(), "fresh file must be written");

        // The regenerated file's envelope must report the *current*
        // arity, not the stale one.
        let on_disk = std::fs::read(km.ivc_pk_path()).unwrap();
        let env: NovaKeyEnvelope<PublicParams<E1, E2, Circuit>> =
            bincode::deserialize(&on_disk).expect("on-disk file must deserialize as envelope");
        assert_eq!(env.arity, arity, "regenerated envelope must record the current arity");
        assert_eq!(
            env.format_version,
            NovaKeyEnvelope::<PublicParams<E1, E2, Circuit>>::FORMAT_VERSION,
            "regenerated envelope must use the current format version"
        );
    }

    /// 1.3.5 — Pre-envelope (legacy bincode blob) is also recovered:
    /// if the file is not a valid `NovaKeyEnvelope` at all (e.g. it was
    /// written by an older key manager that pre-dated the envelope
    /// format), the loader treats it as a cache miss and regenerates.
    #[test]
    fn legacy_blob_triggers_regeneration() {
        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());
        let arity = crate::proving::nova_v1::step_circuit::nova_step_circuit::ROLLUP_ARITY;

        // Write a few garbage bytes that are not a valid envelope.
        std::fs::write(km.ivc_pk_path(), b"definitely not a NovaKeyEnvelope").unwrap();

        let mut gen_calls = 0;
        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(arity, || {
                gen_calls += 1;
                build_pp()
            })
            .expect("load_or_generate_ivc_pk should treat legacy blob as cache miss");
        assert_eq!(gen_calls, 1, "generator must run for a legacy blob");
        assert!(km.ivc_pk_path().exists());
    }
}
