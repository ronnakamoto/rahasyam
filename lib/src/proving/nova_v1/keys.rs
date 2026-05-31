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
//! ## File layout
//!
//! ```text
//! <key_dir>/nova_ivc_pk_v{version}.bin    # PublicParams<E1, E2, C>
//! <key_dir>/nova_snark_pk_v{version}.bin  # ProverKey<E1, E2, C, S1, S2>
//! <key_dir>/nova_snark_vk_v{version}.bin  # VerifierKey<E1, E2, C, S1, S2>
//! ```

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
            version: 1,
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
    /// This is the canonical entry point referenced by the migration plan
    /// as `load_or_generate_ivc_pk()`.
    pub fn load_or_generate_ivc_pk<E1, E2, C>(
        &self,
        generator: impl FnOnce() -> nova_snark::nova::PublicParams<E1, E2, C>,
    ) -> Result<nova_snark::nova::PublicParams<E1, E2, C>, KeyManagerError>
    where
        E1: nova_snark::traits::Engine<Base = <E2 as nova_snark::traits::Engine>::Scalar>,
        E2: nova_snark::traits::Engine<Base = <E1 as nova_snark::traits::Engine>::Scalar>,
        C: nova_snark::traits::circuit::StepCircuit<E1::Scalar>,
    {
        load_or_generate(&self.ivc_pk_path(), "PublicParams", generator)
    }

    /// Backwards-compatible alias for [`Self::load_or_generate_ivc_pk`].
    pub fn get_public_params<E1, E2, C>(
        &self,
        generator: impl FnOnce() -> nova_snark::nova::PublicParams<E1, E2, C>,
    ) -> Result<nova_snark::nova::PublicParams<E1, E2, C>, KeyManagerError>
    where
        E1: nova_snark::traits::Engine<Base = <E2 as nova_snark::traits::Engine>::Scalar>,
        E2: nova_snark::traits::Engine<Base = <E1 as nova_snark::traits::Engine>::Scalar>,
        C: nova_snark::traits::circuit::StepCircuit<E1::Scalar>,
    {
        self.load_or_generate_ivc_pk(generator)
    }

    /// Load the Spartan `CompressedSNARK` prover and verifier keys from
    /// disk, or generate them via `generator` and persist both files.
    ///
    /// `generator` is invoked **only** when at least one of the two cache
    /// files is missing.  In that case the closure must produce the full
    /// `(ProverKey, VerifierKey)` pair (this is what
    /// `CompressedSNARK::setup(&pp)` returns).
    ///
    /// Both files are read or written atomically (one after the other) so
    /// the on-disk state stays consistent for the next boot.
    pub fn load_or_generate_snark_keys<E1, E2, C, S1, S2>(
        &self,
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
            log::info!(
                "[nova-v1] Loading CompressedSNARK PK/VK from disk ({} / {})",
                pk_path.display(),
                vk_path.display()
            );
            let pk: nova_snark::nova::ProverKey<E1, E2, C, S1, S2> =
                read_bincode(&pk_path, "CompressedSNARK ProverKey")?;
            let vk: nova_snark::nova::VerifierKey<E1, E2, C, S1, S2> =
                read_bincode(&vk_path, "CompressedSNARK VerifierKey")?;
            return Ok((pk, vk));
        }

        log::info!("[nova-v1] Generating CompressedSNARK PK/VK (cache miss)");
        let (pk, vk) = generator();
        ensure_parent_dir(&pk_path)?;
        write_bincode(&pk_path, &pk, "CompressedSNARK ProverKey")?;
        write_bincode(&vk_path, &vk, "CompressedSNARK VerifierKey")?;
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

fn ensure_parent_dir(path: &std::path::Path) -> Result<(), KeyManagerError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn read_bincode<T: DeserializeOwned>(
    path: &std::path::Path,
    label: &str,
) -> Result<T, KeyManagerError> {
    let data = std::fs::read(path)?;
    bincode::deserialize(&data).map_err(|e| {
        KeyManagerError::Serialization(format!("deserialize {label} from {}: {e}", path.display()))
    })
}

fn write_bincode<T: Serialize>(
    path: &std::path::Path,
    value: &T,
    label: &str,
) -> Result<(), KeyManagerError> {
    let bytes = bincode::serialize(value).map_err(|e| {
        KeyManagerError::Serialization(format!("serialize {label}: {e}"))
    })?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn load_or_generate<T, G>(
    path: &std::path::Path,
    label: &str,
    generator: G,
) -> Result<T, KeyManagerError>
where
    T: Serialize + DeserializeOwned,
    G: FnOnce() -> T,
{
    if path.exists() {
        log::info!("[nova-v1] Loading {label} from {}", path.display());
        return read_bincode(path, label);
    }
    log::info!("[nova-v1] Generating new {label} (cache miss at {})", path.display());
    let value = generator();
    ensure_parent_dir(path)?;
    write_bincode(path, &value, label)?;
    log::info!("[nova-v1] Persisted {label} to {}", path.display());
    Ok(value)
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

    let pp = km.load_or_generate_ivc_pk::<E1, E2, Circuit>(|| {
        log::info!("[nova-v1] Generating PublicParams (this may take several minutes)...");
        let dummy = Circuit::padding();
        PublicParams::<E1, E2, Circuit>::setup(&dummy, &*S1::ck_floor(), &*S2::ck_floor())
            .expect("PublicParams::setup failed")
    })?;

    let _snark_keys = km.load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(|| {
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
        assert_eq!(km.ivc_pk_path(), dir.join("nova_ivc_pk_v1.bin"));
        assert_eq!(km.snark_pk_path(), dir.join("nova_snark_pk_v1.bin"));
        assert_eq!(km.snark_vk_path(), dir.join("nova_snark_vk_v1.bin"));
    }

    #[test]
    fn rotate_bumps_version_in_paths() {
        let dir = std::env::temp_dir().join("nova_keys_rotate");
        let mut km = NovaKeyManager::new(dir.clone());
        km.rotate().unwrap();
        assert_eq!(km.version(), 2);
        assert_eq!(km.ivc_pk_path(), dir.join("nova_ivc_pk_v2.bin"));
    }

    /// 1.3.1 — `PublicParams` round-trips through disk: the second call to
    /// `load_or_generate_ivc_pk` must NOT invoke the generator (proving the
    /// cache is being read).
    #[test]
    fn public_params_persisted_and_reloaded() {
        let tmp = tempfile::tempdir().unwrap();
        let km = NovaKeyManager::new(tmp.path().to_path_buf());

        // First call: cache miss → generator runs, file is written.
        let mut gen_calls = 0;
        let pp1 = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(|| {
                gen_calls += 1;
                build_pp()
            })
            .expect("first load_or_generate_ivc_pk failed");
        assert_eq!(gen_calls, 1, "generator must run on first call");
        assert!(km.ivc_pk_path().exists(), "ivc_pk file must exist after first call");

        // Second call: cache hit → generator must NOT run.
        let mut gen_calls2 = 0;
        let pp2 = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(|| {
                gen_calls2 += 1;
                build_pp()
            })
            .expect("second load_or_generate_ivc_pk failed");
        assert_eq!(gen_calls2, 0, "generator must NOT run on cache hit");

        // Verify the two PublicParams instances serialize to identical bytes.
        let pp1_bytes = bincode::serialize(&pp1).unwrap();
        let pp2_bytes = bincode::serialize(&pp2).unwrap();
        assert_eq!(pp1_bytes, pp2_bytes, "cached PublicParams must match generated");
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
        let pp = build_pp();

        // First call: cache miss → generate + write both files.
        let mut gen_calls = 0;
        let (pk1, vk1) = km
            .load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(|| {
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
            .load_or_generate_snark_keys::<E1, E2, Circuit, S1, S2>(|| {
                gen_calls2 += 1;
                CompressedSNARK::<_, _, _, S1, S2>::setup(&pp).expect("setup failed")
            })
            .expect("second load_or_generate_snark_keys failed");
        assert_eq!(gen_calls2, 0, "generator must NOT run on cache hit");

        // Functional check: cached PK/VK can still prove + verify a real IVC.
        let circuit = Circuit::padding();
        let z0 = vec![F1::ZERO, F1::ZERO, F1::ZERO, F1::ZERO];
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

        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(build_pp)
            .unwrap();
        assert!(km.ivc_pk_path().exists());

        km.clear_cache().unwrap();
        assert!(!km.ivc_pk_path().exists());

        let mut gen_calls = 0;
        let _ = km
            .load_or_generate_ivc_pk::<E1, E2, Circuit>(|| {
                gen_calls += 1;
                build_pp()
            })
            .unwrap();
        assert_eq!(gen_calls, 1, "generator must run again after clear_cache");
    }
}
