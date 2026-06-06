use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{env, sync::OnceLock};

// rather than pass around what are effectively constant values, or recreate them locally,
// let's use the lazy_static crate to create a global variable that can be used to consume
// settings from anywhere in the code.
pub fn get_settings() -> &'static Settings {
    static SETTINGS: OnceLock<Settings> = OnceLock::new();
    SETTINGS.get_or_init(|| Settings::new().unwrap())
}

/// Deserializes an optional u64, treating empty strings as None.
/// This handles the case where an env var is set but empty (e.g., `NF4_NETWORK__LOG_CHUNK_SIZE=`).
fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    // First try to deserialize as Option<u64> directly
    // If that fails, try as a string and handle empty case
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrU64 {
        U64(u64),
        Str(String),
        None,
    }

    match Option::<StringOrU64>::deserialize(deserializer)? {
        Some(StringOrU64::U64(n)) => Ok(Some(n)),
        Some(StringOrU64::Str(s)) if s.is_empty() => Ok(None),
        Some(StringOrU64::Str(s)) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| de::Error::custom(format!("invalid u64 value: {s}"))),
        Some(StringOrU64::None) | None => Ok(None),
    }
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct Network {
    pub chain_id: u64,
    /// Max blocks per eth_getLogs query. if None, uses chain-specific defaults
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub log_chunk_size: Option<u64>,
}
#[derive(Debug, Deserialize, Serialize, Default, PartialEq, Clone, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletTypeConfig {
    #[default]
    Local,
    Azure,
    #[serde(rename = "YubiWallet")]
    YubiWallet,
    #[serde(rename = "AwsSigner")]
    AwsSigner,
    #[serde(rename = "EYTransactionManager")]
    EyTransactionManager,
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct ClientConfig {
    pub url: String,
    pub log_level: String,
    pub wallet_type: WalletTypeConfig,
    pub db_url: String,
    pub max_event_listener_attempts: Option<u32>,
    pub webhook_url: String,
    pub max_queue_size: Option<u32>,
}

#[derive(Debug, Deserialize, Default, Serialize, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum ProvingSystemIdConfig {
    #[default]
    PlonkV1,
    NovaV1,
}

impl ProvingSystemIdConfig {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProvingSystemIdConfig::PlonkV1 => "plonk-v1",
            ProvingSystemIdConfig::NovaV1 => "nova-v1",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "plonk-v1" | "plonkv1" | "PlonkV1" => Some(ProvingSystemIdConfig::PlonkV1),
            "nova-v1" | "novav1" | "NovaV1" => Some(ProvingSystemIdConfig::NovaV1),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct ProvingSystemConfig {
    #[serde(default)]
    pub active: ProvingSystemIdConfig,
    #[serde(default)]
    pub enabled: Vec<ProvingSystemIdConfig>,
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct ProposerConfig {
    pub url: String,
    pub log_level: String,
    pub wallet_type: WalletTypeConfig,
    pub db_url: String,
    pub block_assembly_max_wait_secs: u64,
    pub block_assembly_target_fill_ratio: f64,
    pub block_assembly_initial_interval_secs: u64,
    pub max_event_listener_attempts: Option<u32>,
    pub block_size: u64,
    #[serde(default)]
    pub proving_system: ProvingSystemConfig,
    /// When `true`, Nova (IVC) blocks are allowed to contain fewer than
    /// `block_size` transactions without padding the deposit list with dummy
    /// proofs. Defaults to `false` because the on-chain `propose_block` path
    /// (see `blockchain_assets/contracts/Nightfall.sol`) still requires the
    /// submitted block to have exactly 64 or 256 transactions; enabling this
    /// flag only makes sense once that contract guard has been relaxed.
    /// The Plonk path ignores this flag and always pads.
    #[serde(default)]
    pub nova_dynamic_block_size: bool,
    /// Upper bound on the number of IVC steps (transactions) the Nova
    /// rollup engine will fold in a single block. **This value MUST be
    /// kept in sync with the on-chain `MAX_STEPS` constant in
    /// `blockchain_assets/contracts/proof_verification/nova_v1/NovaRollupVerifier.sol`**.
    /// Off-chain we reject any block whose transaction count exceeds
    /// this; on-chain the same value is enforced by the contract. If
    /// the two values drift, off-chain will accept blocks the chain
    /// rejects (or vice versa).
    ///
    /// Default matches the on-chain constant as of the current
    /// deployment (`10000`). The `DEFAULT_MAX_STEPS` constant in
    /// `lib::proving::nova_v1::rollup_engine` defaults to the same
    /// value.
    #[serde(default = "default_nova_max_steps")]
    pub nova_max_steps: usize,
}

fn default_nova_max_steps() -> usize {
    10_000
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct DeployerConfig {
    pub log_level: String,
    pub default_proposer_address: String,
    pub default_proposer_url: String,
    pub proposer_stake: u64,
    pub proposer_ding: u64,
    pub proposer_exit_penalty: u64,
    pub proposer_cooling_blocks: u64,
    pub proposer_rotation_blocks: u64,
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct TestConfig {
    pub log_level: String,
}

/// Configuration for the standalone Nova attestation service
/// (`nightfall_attestor`) and the proposer-side client that calls it.
#[derive(Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct AttestorServiceConfig {
    /// URL of the attestation service the proposer calls to obtain a
    /// Nova proof attestation (e.g. `http://attestor:3001`). Empty means
    /// the proposer signs locally with `nova_verifier.attestor_key`
    /// (single-signer dev path), preserving existing behaviour.
    #[serde(default)]
    pub url: String,
    /// Log level for the attestation service binary.
    #[serde(default = "default_attestor_log_level")]
    pub log_level: String,
    /// `address:port` the attestation service binds to.
    #[serde(default = "default_attestor_bind")]
    pub bind: String,
}

fn default_attestor_log_level() -> String {
    "info".to_string()
}

fn default_attestor_bind() -> String {
    "0.0.0.0:3001".to_string()
}

impl Default for AttestorServiceConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            log_level: default_attestor_log_level(),
            bind: default_attestor_bind(),
        }
    }
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct EthereumClientConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Default, Serialize, PartialEq)]
pub struct ContractAddresses {
    pub nightfall: String,
    pub round_robin: String,
    pub x509: String,
    pub verifier: String,
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct NovaVerifierConfig {
    pub g2_x_x0: String,
    pub g2_x_x1: String,
    pub g2_x_y0: String,
    pub g2_x_y1: String,
    pub g2_one_x0: String,
    pub g2_one_x1: String,
    pub g2_one_y0: String,
    pub g2_one_y1: String,
    pub commitment_scheme: u64,
    /// Hex-encoded ECDSA private key of the trusted Nova attestor.
    ///
    /// The proposer signs every Nova `rollup_proof` with this key (see
    /// `nightfall_proposer::driven::nova_prover`) and the deployer
    /// derives the matching address and calls
    /// `NovaRollupVerifier.setAttestor` so the on-chain fail-closed
    /// gate accepts the signed proofs. Empty (the default) means no
    /// attestor is configured: the proposer appends no signature and
    /// the contract rejects all Nova proofs. **Dev/test only** — a
    /// production attestor key must be supplied out-of-band, never
    /// committed.
    #[serde(default)]
    pub attestor_key: String,
}

#[derive(Debug, Deserialize, Default, Serialize)]
#[allow(unused)]
pub struct Contracts {
    pub assets: String,
    pub deployment_file: String,
    pub deploy_contracts: bool,
    pub contract_addresses: ContractAddresses,
}
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct CertificateConfig {
    pub authority_key_identifier: String,
    pub modulus: String,
    pub exponent: u64,
    pub extended_key_usages: Vec<String>,
    pub certificate_policies: Vec<String>,
}

fn default_max_key_download_bytes() -> u64 {
    30 * 1024 * 1024 * 1024 // 30 gb
}

fn default_rpc_rate_limit() -> u32 {
    0 // 0 = unlimited
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[allow(unused)]
pub struct Settings {
    pub signing_key: String,
    #[serde(default)]
    pub swap_cancel_auth_token: Option<String>,
    #[serde(default)]
    pub azure_vault_url: String,
    #[serde(default)]
    pub azure_key_name: String,
    pub log_app_only: bool,
    pub test_x509_certificates: bool,
    pub mock_prover: bool,
    pub skip_key_regeneration: Option<bool>,
    pub nightfall_client: ClientConfig,
    pub contracts: Contracts,
    pub nightfall_deployer: DeployerConfig,
    pub nightfall_proposer: ProposerConfig,
    #[serde(default)]
    pub nightfall_attestor: AttestorServiceConfig,
    pub network: Network,
    pub ethereum_client_url: String,
    pub nightfall_test: TestConfig,
    pub genesis_block: usize,
    pub certificates: CertificateConfig,
    pub nova_verifier: NovaVerifierConfig,
    pub configuration_url: String,
    pub run_mode: String,
    /// Optional upper bound
    /// If not set, default value of 30 GB is used
    #[serde(default = "default_max_key_download_bytes")]
    pub max_key_download_bytes: u64,
    /// Max RPC calls per second (0 = unlimited).
    /// Useful for staying within provider rate limits (e.g., Alchemy free tier: ~8 calls/sec).
    /// Configurable via `NF4_RPC_RATE_LIMIT` env var or `rpc_rate_limit` in nightfall.toml.
    #[serde(default = "default_rpc_rate_limit")]
    pub rpc_rate_limit: u32,
}

impl Settings {
    pub fn new() -> Result<Self, String> {
        let run_mode = env::var("NF4_RUN_MODE").unwrap_or_else(|_| "development".into());

        let figment = Figment::new()
            .join(("run_mode", &run_mode))
            .merge(Toml::file("nightfall.toml").nested())
            .merge(Env::prefixed("NF4_").profile(run_mode.as_str()).split("__"))
            .select(run_mode);

        let mut settings: Settings = figment.extract().map_err(|e| format!("{e}"))?;
        // Check the wallet type and read additional Azure-specific settings
        if settings.nightfall_client.wallet_type == WalletTypeConfig::Azure
            || settings.nightfall_proposer.wallet_type == WalletTypeConfig::Azure
        {
            settings.azure_vault_url = env::var("AZURE_VAULT_URL").unwrap_or_default();
            settings.azure_key_name = env::var("PROPOSER_SIGNING_KEY_NAME")
                .or_else(|_| env::var("CLIENT_SIGNING_KEY_NAME"))
                .or_else(|_| env::var("AZURE_KEY_NAME"))
                .unwrap_or_default();
        }

        // Override proving system via environment variable
        if let Ok(ps_override) = env::var("NIGHTFALL_PROVING_SYSTEM") {
            if let Some(ps_config) = ProvingSystemIdConfig::from_str(&ps_override) {
                settings.nightfall_proposer.proving_system.active = ps_config;
            }
        }

        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    #[test]
    #[serial]
    fn test_config() {
        let tmp_signing_key = env::var("NF4_SIGNING_KEY").ok();
        let tmp_run_mode = env::var("NF4_RUN_MODE").ok();

        env::set_var("NF4_SIGNING_KEY", "0x2a");
        env::set_var("NF4_RUN_MODE", "development");

        // Load settings *after* setting environment variables
        let s = Settings::new().unwrap();

        // Assert that the loaded settings match what we set
        assert_eq!(
            s.signing_key.as_str(),
            "0x2a",
            "The signing key should be overridden by the environment variable."
        );
        assert_eq!(
            s.run_mode, "development",
            "The run mode should be set to development."
        );

        // Clean up environment variables using match for correct restoration
        match tmp_signing_key {
            Some(val) => env::set_var("NF4_SIGNING_KEY", val),
            None => env::remove_var("NF4_SIGNING_KEY"),
        }
        match tmp_run_mode {
            Some(val) => env::set_var("NF4_RUN_MODE", val),
            None => env::remove_var("NF4_RUN_MODE"),
        }
    }

    #[test]
    #[serial]
    fn test_override() {
        let tmp_db_url = env::var("NF4_NIGHTFALL_CLIENT__DB_URL").ok();
        let tmp_run_mode = env::var("NF4_RUN_MODE").ok();

        // Set environment variables for the test
        env::set_var(
            "NF4_NIGHTFALL_CLIENT__DB_URL",
            "mongodb://nf4_db_client2:27017",
        );
        // Crucially, set NF4_RUN_MODE before Settings::new()
        env::set_var("NF4_RUN_MODE", "development");

        // Load settings *after* setting environment variables
        let s = Settings::new().unwrap();

        // Assert that the loaded setting matches what we set
        assert_eq!(
            s.nightfall_client.db_url.as_str(),
            "mongodb://nf4_db_client2:27017",
            "The DB URL should be overridden by the environment variable."
        );

        assert_eq!(
            s.run_mode, "development",
            "The run mode should be set to development."
        );

        // Clean up environment variables using match
        match tmp_db_url {
            Some(val) => env::set_var("NF4_NIGHTFALL_CLIENT__DB_URL", val),
            None => env::remove_var("NF4_NIGHTFALL_CLIENT__DB_URL"),
        }
        match tmp_run_mode {
            Some(val) => env::set_var("NF4_RUN_MODE", val),
            None => env::remove_var("NF4_RUN_MODE"),
        }
    }

    #[test]
    #[serial]
    fn test_override_with_profile() {
        // Backup original env vars
        let tmp_db_url = env::var("NF4_NIGHTFALL_CLIENT__DB_URL").ok();
        let tmp_run_mode = env::var("NF4_RUN_MODE").ok();

        // Set environment variables for the test
        env::set_var(
            "NF4_NIGHTFALL_CLIENT__DB_URL",
            "mongodb://nf4_db_client2:27017",
        );
        env::set_var("NF4_RUN_MODE", "development");

        // Load settings *after* setting environment variables
        let s = Settings::new().unwrap();

        // Assert that the loaded setting matches what we set
        assert_eq!(
            s.nightfall_client.db_url.as_str(),
            "mongodb://nf4_db_client2:27017",
            "The DB URL should be overridden by the environment variable for the 'development' profile."
        );

        assert_eq!(
            s.run_mode, "development",
            "The run mode should be set to development."
        );

        // Clean up environment variables to avoid affecting other tests
        match tmp_db_url {
            Some(val) => env::set_var("NF4_NIGHTFALL_CLIENT__DB_URL", val),
            None => env::remove_var("NF4_NIGHTFALL_CLIENT__DB_URL"),
        }

        match tmp_run_mode {
            Some(val) => env::set_var("NF4_RUN_MODE", val),
            None => env::remove_var("NF4_RUN_MODE"),
        }
    }

    #[test]
    #[serial]
    fn test_proving_system_env_override() {
        let tmp_run_mode = env::var("NF4_RUN_MODE").ok();
        let tmp_proving_system = env::var("NIGHTFALL_PROVING_SYSTEM").ok();

        // Set environment variables
        env::set_var("NIGHTFALL_PROVING_SYSTEM", "nova-v1");
        env::set_var("NF4_RUN_MODE", "development");

        // Load settings *after* setting environment variables
        let s = Settings::new().unwrap();

        // Assert that the proving system is overridden to NovaV1
        assert_eq!(
            s.nightfall_proposer.proving_system.active,
            ProvingSystemIdConfig::NovaV1,
            "The proving system should be overridden to NovaV1 by environment variable."
        );

        // Clean up environment variables
        match tmp_proving_system {
            Some(val) => env::set_var("NIGHTFALL_PROVING_SYSTEM", val),
            None => env::remove_var("NIGHTFALL_PROVING_SYSTEM"),
        }
        match tmp_run_mode {
            Some(val) => env::set_var("NF4_RUN_MODE", val),
            None => env::remove_var("NF4_RUN_MODE"),
        }
    }

    #[test]
    #[serial]
    fn test_proving_system_env_override_plonk() {
        let tmp_run_mode = env::var("NF4_RUN_MODE").ok();
        let tmp_proving_system = env::var("NIGHTFALL_PROVING_SYSTEM").ok();

        // Set environment variables
        env::set_var("NIGHTFALL_PROVING_SYSTEM", "plonk-v1");
        env::set_var("NF4_RUN_MODE", "development");

        // Load settings *after* setting environment variables
        let s = Settings::new().unwrap();

        // Assert that the proving system is overridden to PlonkV1
        assert_eq!(
            s.nightfall_proposer.proving_system.active,
            ProvingSystemIdConfig::PlonkV1,
            "The proving system should be overridden to PlonkV1 by environment variable."
        );

        // Clean up environment variables
        match tmp_proving_system {
            Some(val) => env::set_var("NIGHTFALL_PROVING_SYSTEM", val),
            None => env::remove_var("NIGHTFALL_PROVING_SYSTEM"),
        }
        match tmp_run_mode {
            Some(val) => env::set_var("NF4_RUN_MODE", val),
            None => env::remove_var("NF4_RUN_MODE"),
        }
    }

    #[test]
    fn test_proving_system_id_config_from_str() {
        assert_eq!(
            ProvingSystemIdConfig::from_str("plonk-v1"),
            Some(ProvingSystemIdConfig::PlonkV1)
        );
        assert_eq!(
            ProvingSystemIdConfig::from_str("nova-v1"),
            Some(ProvingSystemIdConfig::NovaV1)
        );
        assert_eq!(
            ProvingSystemIdConfig::from_str("unknown"),
            None
        );
    }
}
