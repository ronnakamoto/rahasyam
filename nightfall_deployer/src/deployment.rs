use crate::vk_contract::write_vk_to_nightfall_toml;
use alloy::{hex, primitives::Address};
use configuration::{
    addresses::{Addresses, Sources},
    settings::{ProvingSystemIdConfig, Settings},
};
use jf_plonk::recursion::RecursiveProver;

use lib::blockchain_client::BlockchainClientConnection;
use log::{debug, error, info};
use nightfall_proposer::driven::rollup_prover::RollupProver;
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
};

fn merge_key_counts(block_size: u64) -> anyhow::Result<(usize, usize)> {
    match block_size {
        64 => Ok((1, 2)),
        256 => Ok((2, 3)),
        _ => anyhow::bail!(
            "Unsupported block_size={block_size} for real-prover key validation (supported: 64, 256)"
        ),
    }
}

fn ensure_plonk_real_prover_keys_exist(settings: &Settings) -> anyhow::Result<()> {
    let keys_dir = std::env::current_dir()?
        .join("configuration")
        .join("bin/keys");
    let (bn254_merge_count, grumpkin_merge_count) =
        merge_key_counts(settings.nightfall_proposer.block_size)?;

    let mut required_files = vec![
        "proving_key".to_string(),
        "base_bn254_pk".to_string(),
        "base_grumpkin_pk".to_string(),
        "decider_pk".to_string(),
        "decider_vk".to_string(),
    ];

    for i in 0..bn254_merge_count {
        required_files.push(format!("merge_bn254_pk_{i}"));
    }
    for i in 0..grumpkin_merge_count {
        required_files.push(format!("merge_grumpkin_pk_{i}"));
    }

    let missing_files: Vec<String> = required_files
        .into_iter()
        .filter(|name| !keys_dir.join(name).is_file())
        .collect();

    if !missing_files.is_empty() {
        anyhow::bail!(
            "Missing real-prover key files in {}: {}. Generate them first with: NF4_MOCK_PROVER=false cargo run --release --bin key_generation",
            keys_dir.display(),
            missing_files.join(", ")
        );
    }
    Ok(())
}

fn ensure_nova_keys_directory() -> anyhow::Result<PathBuf> {
    let nova_keys_dir = std::env::current_dir()?
        .join("configuration")
        .join("bin/nova_keys");
    std::fs::create_dir_all(&nova_keys_dir)?;
    Ok(nova_keys_dir)
}

fn prepare_verifier_material(settings: &Settings) -> anyhow::Result<()> {
    if settings.mock_prover || !settings.contracts.deploy_contracts {
        return Ok(());
    }

    match settings.nightfall_proposer.proving_system.active {
        ProvingSystemIdConfig::PlonkV1 => {
            ensure_plonk_real_prover_keys_exist(settings)?;
            let vk = RollupProver::get_decider_vk();
            let _ = write_vk_to_nightfall_toml(&vk);
        }
        ProvingSystemIdConfig::NovaV1 | ProvingSystemIdConfig::NovaBlsV1 => {
            let nova_keys_dir = ensure_nova_keys_directory()?;
            info!(
                "Active proving system is NovaV1; skipping PLONK decider_vk wiring. Nova key cache path: {}",
                nova_keys_dir.display()
            );
        }
        ProvingSystemIdConfig::UltraHonkV1 => {
            // UltraHonkV1 proves per-transaction (client) proofs but still uses
            // the Nova rollup engine, so the Nova key cache directory must exist.
            let nova_keys_dir = ensure_nova_keys_directory()?;
            info!(
                "Active proving system is UltraHonkV1 (Nova rollup); skipping PLONK decider_vk wiring. Nova key cache path: {}",
                nova_keys_dir.display()
            );
        }
    }

    Ok(())
}

fn proxies_from_broadcast(path: &Path) -> anyhow::Result<HashMap<&'static str, Address>> {
    let v: Value = serde_json::from_reader(File::open(path)?)?;
    let txs = v
        .get("transactions")
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow::anyhow!("no transactions in broadcast"))?;

    let mut map = HashMap::new();
    let mut last_impl_name: Option<String> = None;

    for tx in txs {
        let ttype = tx
            .get("transactionType")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let cname = tx
            .get("contractName")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let caddr_s = tx.get("contractAddress").and_then(|x| x.as_str());

        // Upgrades.deployUUPSProxy deploys: implementation (CREATE, contractName = Nightfall/RoundRobin/X509), then ERC1967Proxy (CREATE)
        if ttype == "CREATE" && cname != "ERC1967Proxy" && !cname.is_empty() {
            last_impl_name = Some(cname.to_string());
        }

        if ttype == "CREATE" && cname == "ERC1967Proxy" {
            if let (Some(prev), Some(addr_s)) = (last_impl_name.as_deref(), caddr_s) {
                let addr: Address = addr_s.parse()?;
                if prev.contains("Nightfall") {
                    map.insert("nightfall", addr);
                } else if prev.contains("RoundRobin") {
                    map.insert("round_robin", addr);
                } else if prev.contains("X509") {
                    map.insert("x509", addr);
                } else if prev.contains("RollupProofVerifier") {
                    map.insert("verifier", addr);
                } else if prev.contains("NovaRollupVerifier") {
                    map.insert("nova_verifier", addr);
                } else if prev.contains("NovaCommitteeVerifier") {
                    map.insert("committee_verifier", addr);
                }
            }
        }

        // Capture direct (non-proxy) deployments as well
        if ttype == "CREATE" && cname != "ERC1967Proxy" && !cname.is_empty() {
            if let Some(addr_s) = caddr_s {
                let addr: Address = addr_s.parse()?;
                if cname.contains("ProofSystemRouter") && !map.contains_key("verifier") {
                    map.insert("verifier", addr);
                } else if cname.contains("NovaCommitteeVerifier")
                    && !map.contains_key("committee_verifier")
                {
                    map.insert("committee_verifier", addr);
                } else if cname.contains("NovaRollupVerifier") && !map.contains_key("nova_verifier")
                {
                    map.insert("nova_verifier", addr);
                }
            }
        }
    }

    if map.is_empty() {
        anyhow::bail!("no proxies found in broadcast");
    }
    Ok(map)
}

pub async fn deploy_contracts(settings: &Settings) -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("NF4_RUN_MODE", &settings.run_mode);

    // Clean up potentially corrupted build-info files from Docker build stage
    let build_info_path = PathBuf::from("blockchain_assets/artifacts/build-info");
    if build_info_path.exists() {
        info!("Cleaning build-info directory to ensure fresh compilation");
        std::fs::remove_dir_all(&build_info_path).ok();
    }

    // Also clean cache to ensure deterministic compilation
    let cache_path = PathBuf::from("blockchain_assets/cache");
    if cache_path.exists() {
        info!("Cleaning cache directory");
        std::fs::remove_dir_all(&cache_path).ok();
    }

    prepare_verifier_material(settings)?;

    // Force a clean rebuild to generate complete build-info files for OpenZeppelin validation.
    // `forge build --force` can still leave stale/partial artifacts around, which makes
    // @openzeppelin/foundry-upgrades fail during the deployment script.
    info!("Cleaning contract artifacts with forge");
    forge_command(&["clean"]);

    info!("Building contracts with forge");
    forge_command(&["build"]);

    info!("Deploying contracts with forge script");
    forge_command(&[
        "script",
        "Deployer",
        "--fork-url",
        &settings.ethereum_client_url,
        "--broadcast",
    ]);

    // -------- read Foundry broadcast --------
    let cwd = std::env::current_dir()?;
    let path_out = cwd
        .join(&settings.contracts.deployment_file)
        .join(settings.network.chain_id.to_string())
        .join("run-latest.json");

    if !path_out.is_file() {
        return Err(format!("Deployment log file not found: {path_out:?}").into());
    }
    let mut addresses = Addresses {
        chain_id: settings.network.chain_id,
        nightfall: Address::ZERO,
        round_robin: Address::ZERO,
        x509: Address::ZERO,
        verifier: Address::ZERO,
        nova_verifier: Address::ZERO,
        committee_verifier: Address::ZERO,
    };
    // -------- replace with *proxy* addresses from broadcast --------
    match proxies_from_broadcast(&path_out) {
        Ok(proxy_map) => {
            if let Some(a) = proxy_map.get("nightfall") {
                addresses.nightfall = *a;
            }
            if let Some(a) = proxy_map.get("round_robin") {
                addresses.round_robin = *a;
            }
            if let Some(a) = proxy_map.get("x509") {
                addresses.x509 = *a;
            }
            if let Some(a) = proxy_map.get("verifier") {
                addresses.verifier = *a;
            }
            if let Some(a) = proxy_map.get("nova_verifier") {
                addresses.nova_verifier = *a;
            }
            if let Some(a) = proxy_map.get("committee_verifier") {
                addresses.committee_verifier = *a;
            }
            if settings.mock_prover {
                if addresses.nightfall == Address::ZERO
                    || addresses.round_robin == Address::ZERO
                    || addresses.x509 == Address::ZERO
                {
                    error!("Missing proxy addresses after extraction");
                    return Err("Failed to extract all proxy addresses from deployment".into());
                }
                info!(
                    "Extracted proxy addresses: nightfall={:?}, round_robin={:?}, x509={:?}",
                    addresses.nightfall, addresses.round_robin, addresses.x509
                );
            } else {
                let has_plonk = addresses.verifier != Address::ZERO;
                let has_nova = addresses.nova_verifier != Address::ZERO;
                if addresses.nightfall == Address::ZERO
                    || addresses.round_robin == Address::ZERO
                    || addresses.x509 == Address::ZERO
                    || (!has_plonk && !has_nova)
                {
                    error!("Missing proxy addresses after extraction");
                    return Err("Failed to extract all proxy addresses from deployment".into());
                }
                info!(
                    "Extracted proxy addresses: nightfall={:?}, round_robin={:?}, x509={:?}, verifier={:?}, nova_verifier={:?}",
                    addresses.nightfall, addresses.round_robin, addresses.x509, addresses.verifier, addresses.nova_verifier
                );
            }
        }
        Err(e) => {
            error!("Failed to parse deployment broadcast file: {e}");
            return Err(
                format!("Deployment failed: could not extract proxy addresses: {e}").into(),
            );
        }
    }
    // -------- Save addresses to file --------
    let file_path = PathBuf::from("/app/configuration/toml/addresses.toml");
    info!("Saving addresses for chain_id: {}", addresses.chain_id);
    addresses.save(Sources::File(file_path)).await?;
    info!("Addresses saved successfully");

    save_deployed_hashes(&addresses).await?;

    Ok(())
}

/// Save the hashes of the deployed contract implementations
/// This allows proposer/client to verify they are using the correct contracts
async fn save_deployed_hashes(addresses: &Addresses) -> Result<(), Box<dyn std::error::Error>> {
    use lib::{
        initialisation::get_blockchain_client_connection,
        verify_contract::{get_onchain_code_hash, get_proxy_implementation},
    };

    info!("Calculating deployed contract hashes for verification");

    let blockchain_client = get_blockchain_client_connection()
        .await
        .read()
        .await
        .get_client();
    let provider = blockchain_client.root();

    // Get implementation addresses
    let nf_impl = get_proxy_implementation(&provider, addresses.nightfall).await?;
    let rr_impl = get_proxy_implementation(&provider, addresses.round_robin).await?;
    let x509_impl = get_proxy_implementation(&provider, addresses.x509).await?;

    // Get on-chain bytecode hashes (with metadata stripped)
    let nf_hash = get_onchain_code_hash(&provider, nf_impl).await?;
    let rr_hash = get_onchain_code_hash(&provider, rr_impl).await?;
    let x509_hash = get_onchain_code_hash(&provider, x509_impl).await?;

    info!("Nightfall implementation hash: 0x{}", hex::encode(nf_hash));
    info!("RoundRobin implementation hash: 0x{}", hex::encode(rr_hash));
    info!("X509 implementation hash: 0x{}", hex::encode(x509_hash));

    // Save to TOML file that will be read by proposer/client
    let hashes_path = PathBuf::from("/app/configuration/toml/contract_hashes.toml");
    let hashes_toml = format!(
        "nightfall_hash = \"{}\"\nround_robin_hash = \"{}\"\nx509_hash = \"{}\"\n",
        hex::encode(nf_hash),
        hex::encode(rr_hash),
        hex::encode(x509_hash)
    );
    std::fs::write(&hashes_path, hashes_toml)?;
    info!("Contract hashes saved to {hashes_path:?}");

    Ok(())
}

/// Function should only be called after we have checked forge is installed by running 'which forge'
pub fn forge_command(command: &[&str]) {
    debug!("DEBUG: Running forge command: {command:?}"); // Use info! as forge_command already uses info!
    let output = std::process::Command::new("forge").args(command).output();

    match output {
        Ok(o) => {
            if o.status.success() {
                info!(
                    "Command 'forge {:?}' executed successfully: {}",
                    command,
                    String::from_utf8_lossy(&o.stdout)
                );
            } else {
                let signal_hint = match o.status.signal() {
                    Some(4) => "\nProcess was terminated by SIGILL (illegal instruction). If this is running under Docker on Apple Silicon, rebuild/run the deployer for the host-native architecture instead of forcing linux/amd64.",
                    _ => "",
                };
                panic!(
                "Command 'forge {:?}' executed with failing error code: {:?}{signal_hint}\nStandard Output: {}\nStandard Error: {}",
                command,
                o.status,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            }
        }
        Err(e) => {
            panic!("Command 'forge {command:?}' ran into an error without executing: {e}");
        }
    }
}

// Todo: fix unwrap panic in test and re-enable test
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use alloy::providers::{Provider, ProviderBuilder};
//     use alloy_node_bindings::Anvil;
//     use configuration::addresses::get_addresses;
//     use nightfall_bindings::artifacts::Nightfall;
//     use std::{fs, path::Path};
//     use tokio::task::spawn_blocking;
//     use url::Url;
//     use std::{fs, path::Path};

//     use nightfall_bindings::artifacts::Nightfall;
//     use tokio::task::spawn_blocking;

//     // NB: This test requires Anvil to be installed (it will use Anvil to simulate a blockchain).
//     // Restart VS Code after installing Anvil so that it's in your PATH otherwise VS Code won't find it!
//     #[tokio::test]
//     async fn test_deploy_contracts() {
//         // fire up a blockchain simulator
//         let mut settings = Settings::new().unwrap();
//         std::env::set_var(
//             "NF4_SIGNING_KEY",
//             "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
//         );
//         settings.ethereum_client_url = "http://localhost:8545".to_string(); // we're running bare metal so a docker url won't work
//         let url = Url::parse(&settings.ethereum_client_url).unwrap();
//         let anvil = Anvil::new()
//             .port(
//                 url.port()
//                     .expect("Could not get Anvil instance. Have you installed it?"),
//             )
//             .spawn();
//         tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
//         // set the current working directory to be the project root
//         let root = "../";
//         std::env::set_current_dir(root).unwrap();

//         // run the deploy function and get the contract addresses

//         deploy_contracts(&settings).await.unwrap();
//         // get a blockchain provider so we can interrogate the deployed code
//         let provider = ProviderBuilder::new()
//             .disable_recommended_fillers()
//             .connect_http(anvil.endpoint_url());

//         let code = provider
//             // use spawn blocking because the blocking reqwest client is not async and it complains (but we need loading the addresses to be sync elsewhere)
//             .get_code_at(spawn_blocking(get_addresses).await.unwrap().nightfall())
//             .await
//             .unwrap();
//         assert_eq!(code, Nightfall::DEPLOYED_BYTECODE);
//         // clean up by remvoing the addresses file and directory that this test created
//         fs::remove_dir_all(Path::new("configuration/toml")).unwrap();
//     }
// }
