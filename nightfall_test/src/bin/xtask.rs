//! `xtask` — the developer-facing fast-iteration driver for the Nova
//! + Nightfall integration loop.
//!
//! Run with `cargo xtask <subcommand>` (the alias is defined in the
//! workspace `.cargo/config.toml`).
//!
//! Subcommands:
//!
//! - `infra-up` / `infra-down` / `infra-logs` — manage the
//!   `docker-compose.dev-infra.yml` ring (MongoDB + anvil). These
//!   wrap `docker compose -f` so you don't have to remember the
//!   `-f` flag.
//! - `nova-keygen` — pregenerate Nova PublicParams + SNARK PK/VK into
//!   `./configuration/bin/nova_keys/`. Skip if already generated.
//! - `nova-build` — release build of the proposer / client / test
//!   binaries with `--features nova-v1`. ~3 min on first run.
//! - `nova-e2e` — run the in-process e2e Nova prover regression
//!   tests in `nightfall_proposer::driven::nova_prover_e2e_tests`,
//!   **one test per process** (the MongoDB driver's connection pool
//!   does not recover between e2e tests in the same process; the
//!   `cargo nova-prover -- --ignored --test-threads=1` invocation
//!   hits a `ServerSelection` timeout on the second test). Use this
//!   instead of `cargo nova-prover -- --ignored ...`.
//! - `nova-fast` — end-to-end 3-tx scenario on host binaries + Docker
//!   infra. Skips deploy / keygen if their outputs already exist on
//!   disk; pass `--no-deploy` / `--no-keygen` to force a particular
//!   step on or off. Equivalent to `docker compose --profile development up`
//!   minus the image build and minus the Rosetta emulation for
//!   PublicParams deserialization.
//! - `down` — stop the background proposer / client processes started
//!   by `nova-fast`. Keeps the infra ring up.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const COMPOSE_FILE: &str = "docker-compose.dev-infra.yml";
const PROPOSER_BIN: &str = "nightfall_proposer";
const CLIENT_BIN: &str = "nightfall_client";
const ANVIL_RPC_URL: &str = "http://localhost:8545";
const MONGO_URL: &str = "mongodb://localhost:27017";
const PROPOSER_URL: &str = "http://localhost:3001";
const CLIENT_URL: &str = "http://localhost:3000";

#[derive(Debug)]
enum Cmd {
    InfraUp,
    InfraDown { volumes: bool },
    InfraLogs,
    NovaKeygen,
    NovaBuild,
    NovaE2e,
    NovaFast { skip_deploy: bool, skip_keygen: bool },
    Down,
}

fn parse_cmd() -> Result<Cmd> {
    let mut args = std::env::args().skip(1);
    let sub = args.next().context("missing subcommand")?;
    match sub.as_str() {
        "infra-up" => Ok(Cmd::InfraUp),
        "infra-down" => {
            let volumes = args.any(|a| a == "--volumes");
            Ok(Cmd::InfraDown { volumes })
        }
        "infra-logs" => Ok(Cmd::InfraLogs),
        "nova-keygen" => Ok(Cmd::NovaKeygen),
        "nova-build" => Ok(Cmd::NovaBuild),
        "nova-e2e" => Ok(Cmd::NovaE2e),
        "nova-fast" => {
            let mut skip_deploy = false;
            let mut skip_keygen = false;
            for a in args {
                if a == "--skip-deploy" {
                    skip_deploy = true;
                } else if a == "--skip-keygen" {
                    skip_keygen = true;
                } else {
                    bail!("unknown flag for nova-fast: {a}");
                }
            }
            Ok(Cmd::NovaFast {
                skip_deploy,
                skip_keygen,
            })
        }
        "down" => Ok(Cmd::Down),
        "help" | "-h" | "--help" => {
            print_help();
            std::process::exit(0);
        }
        other => bail!("unknown subcommand: {other}\n\n{}", HELP),
    }
}

const HELP: &str = "Usage: cargo xtask <subcommand>

Subcommands:
  infra-up                   Start MongoDB + anvil containers
  infra-down [--volumes]     Stop the infra ring (drop volume to wipe DB)
  infra-logs                 Tail the infra container logs
  nova-keygen                Pregenerate Nova keys into ./configuration/bin/nova_keys
  nova-build                 Release-build the proposer / client / test binaries
  nova-e2e                   Run the in-process Nova prover e2e regression
                             tests, one test per cargo invocation. This
                             avoids the mongodb-driver connection-pool
                             timeout that hits `cargo nova-prover -- --ignored`
                             when two e2e tests share a process.
  nova-fast [--skip-deploy] [--skip-keygen]
                             End-to-end 3-tx scenario on host binaries + Docker infra
  down                       Stop the background proposer / client processes
  help                       Print this help
";

fn print_help() {
    print!("{HELP}");
}

fn main() -> Result<()> {
    let cmd = parse_cmd()?;
    match cmd {
        Cmd::InfraUp => infra_up(),
        Cmd::InfraDown { volumes } => infra_down(volumes),
        Cmd::InfraLogs => infra_logs(),
        Cmd::NovaKeygen => nova_keygen(),
        Cmd::NovaBuild => nova_build(),
        Cmd::NovaE2e => nova_e2e(),
        Cmd::NovaFast {
            skip_deploy,
            skip_keygen,
        } => nova_fast(skip_deploy, skip_keygen),
        Cmd::Down => down(),
    }
}

// ---------------------------------------------------------------------------
// Infra ring
// ---------------------------------------------------------------------------

fn infra_up() -> Result<()> {
    println!("[xtask] Starting dev-infra ring ({COMPOSE_FILE})…");
    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            COMPOSE_FILE,
            "up",
            "-d",
            "--wait",
        ])
        .status()
        .context("failed to invoke docker compose")?;
    if !status.success() {
        bail!("docker compose up failed: {status}");
    }
    wait_for_health()?;
    println!("[xtask] Dev-infra ring up: MongoDB on {MONGO_URL}, anvil on {ANVIL_RPC_URL}");
    Ok(())
}

fn infra_down(volumes: bool) -> Result<()> {
    let mut args = vec!["compose", "-f", COMPOSE_FILE, "down"];
    if volumes {
        args.push("--volumes");
    }
    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("failed to invoke docker compose")?;
    if !status.success() {
        bail!("docker compose down failed: {status}");
    }
    if volumes {
        println!("[xtask] Dev-infra ring down (MongoDB volume wiped).");
    } else {
        println!("[xtask] Dev-infra ring down (MongoDB volume preserved).");
    }
    Ok(())
}

fn infra_logs() -> Result<()> {
    let status = Command::new("docker")
        .args(["compose", "-f", COMPOSE_FILE, "logs", "-f", "--tail=100"])
        .status()
        .context("failed to invoke docker compose")?;
    if !status.success() {
        bail!("docker compose logs failed: {status}");
    }
    Ok(())
}

fn wait_for_health() -> Result<()> {
    println!("[xtask] Waiting for MongoDB on {MONGO_URL}…");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if mongodb_ping().is_ok() {
            println!("[xtask] MongoDB reachable.");
            break;
        }
        if Instant::now() > deadline {
            bail!("MongoDB did not become healthy within 30s on {MONGO_URL}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("[xtask] Waiting for anvil on {ANVIL_RPC_URL}…");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if anvil_chain_id().is_ok() {
            println!("[xtask] anvil reachable.");
            break;
        }
        if Instant::now() > deadline {
            bail!("anvil did not become healthy within 30s on {ANVIL_RPC_URL}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn mongodb_ping() -> Result<()> {
    let out = Command::new("docker")
        .args([
            "compose",
            "-f",
            COMPOSE_FILE,
            "exec",
            "-T",
            "mongo",
            "mongosh",
            "--quiet",
            "--eval",
            "db.runCommand({ping:1}).ok",
        ])
        .output()
        .context("mongo ping exec failed")?;
    if !out.status.success() {
        bail!("mongo ping returned non-zero");
    }
    let s = String::from_utf8_lossy(&out.stdout);
    if s.trim() != "1" {
        bail!("mongo ping did not return 1: {s}");
    }
    Ok(())
}

fn anvil_chain_id() -> Result<()> {
    // `cast` is available in the foundry image; on the host we don't
    // require it. If the host has it, we use it; otherwise we hit
    // the JSON-RPC directly via curl.
    let out = Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data",
            r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
            ANVIL_RPC_URL,
        ])
        .output()
        .context("curl eth_chainId failed")?;
    if !out.status.success() {
        bail!("eth_chainId returned non-zero");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nova keygen / build
// ---------------------------------------------------------------------------

fn nova_keygen() -> Result<()> {
    let key_dir = nova_key_dir();
    if key_dir.join("nova_ivc_pk_v3.bin").exists() {
        println!("[xtask] Nova keys already present in {}; skipping keygen.", key_dir.display());
        return Ok(());
    }
    println!("[xtask] Pregenerating Nova keys into {}…", key_dir.display());
    let status = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--features",
            "nova-v1",
            "-p",
            "nightfall_deployer",
            "--bin",
            "key_generation",
        ])
        .env("NF4_RUN_MODE", "local")
        .env("NF4_MOCK_PROVER", "false")
        .status()
        .context("failed to run key_generation")?;
    if !status.success() {
        bail!("key_generation failed: {status}");
    }
    Ok(())
}

fn nova_build() -> Result<()> {
    println!("[xtask] Building proposer / client / test with --features nova-v1 (release)…");
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--features",
            "nova-v1",
            "-p",
            "nightfall_proposer",
            "-p",
            "nightfall_client",
            "-p",
            "nightfall_test",
        ])
        .status()
        .context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build failed: {status}");
    }
    Ok(())
}

/// Run the in-process e2e Nova prover regression tests in
/// `nightfall_proposer::driven::nova_prover_e2e_tests`, **one test
/// per `cargo test` invocation**.
///
/// Why one per process: the proposer's `get_db_connection()` caches
/// the `mongodb::Client` in a `tokio::sync::OnceCell`. When the
/// first e2e test runs and drops Mongo collections, the client's
/// background topology monitor gets stuck in a "primary unknown"
/// state, and the second test's `find({})` hits a `ServerSelection`
/// timeout. No amount of `tokio::time::sleep` between tests
/// recovers the pool. Running each test in a fresh process gives
/// each one a fresh `OnceCell` and a fresh connection pool.
fn nova_e2e() -> Result<()> {
    println!("[xtask] Running Nova prover e2e tests (one cargo invocation per test)…");

    // Order matters: run the 1-deposit test first because it
    // initializes the tree collections. The 2-blocks test then
    // exercises the Neptune IMT hydration path on top of the
    // existing indexed-leaves state.
    let tests = [
        "driven::nova_prover_e2e_tests::e2e_one_real_deposit_produces_valid_on_chain_blob",
        "driven::nova_prover_e2e_tests::e2e_two_blocks_with_transfer_hydrates_imt",
    ];

    let mut any_failed = false;
    for test in tests {
        println!("\n[xtask] === {test} ===");
        let status = Command::new("cargo")
            .args([
                "test",
                "-p",
                "nightfall_proposer",
                "--features",
                "nova-v1",
                "--release",
                "--lib",
                test,
                "--",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .status()
            .with_context(|| format!("failed to run cargo test for {test}"))?;
        if !status.success() {
            eprintln!("[xtask] {test} FAILED");
            any_failed = true;
        } else {
            println!("[xtask] {test} passed");
        }
    }

    if any_failed {
        bail!("one or more e2e tests failed");
    }
    println!("\n[xtask] All Nova prover e2e tests passed.");
    Ok(())
}

fn nova_key_dir() -> PathBuf {
    // Mirrors NovaKeyManager::with_default_dir() in
    // lib/src/proving/nova_v1/keys.rs: NF4_NOVA_KEY_DIR if set, else
    // ./configuration/bin/nova_keys.
    if let Ok(p) = std::env::var("NF4_NOVA_KEY_DIR") {
        PathBuf::from(p)
    } else {
        PathBuf::from("configuration/bin/nova_keys")
    }
}

// ---------------------------------------------------------------------------
// nova-fast: 3-tx scenario
// ---------------------------------------------------------------------------

fn nova_fast(skip_deploy: bool, skip_keygen: bool) -> Result<()> {
    let total_start = Instant::now();

    // 1. Make sure infra is up.
    if !mongodb_ping().is_ok() || anvil_chain_id().is_err() {
        println!("[xtask] Dev-infra ring not healthy; bringing it up…");
        infra_up()?;
    } else {
        println!("[xtask] Dev-infra ring already healthy.");
    }

    // 2. Build the binaries if they're missing.
    if !bin_path(PROPOSER_BIN).exists() || !bin_path(CLIENT_BIN).exists() {
        nova_build()?;
    } else {
        println!("[xtask] Proposer / client binaries already built.");
    }

    // 3. Generate keys if needed.
    if !skip_keygen {
        nova_keygen()?;
    }

    // 4. Deploy contracts.
    if !skip_deploy {
        deploy_contracts()?;
    } else {
        println!("[xtask] Skipping contract deploy (--skip-deploy).");
    }

    // 5. Start proposer + client in the background.
    let proposer = spawn_host_bin(PROPOSER_BIN)?;
    println!("[xtask] Proposer spawned (pid={}).", proposer.id());
    let client = spawn_host_bin(CLIENT_BIN)?;
    println!("[xtask] Client spawned (pid={}).", client.id());

    // 6. Wait for /v1/health on both.
    wait_for_http(&format!("{CLIENT_URL}/v1/health"), Duration::from_secs(60))?;
    wait_for_http(&format!("{PROPOSER_URL}/v1/health"), Duration::from_secs(60))?;

    // 7. Run the 3-tx scenario (deposit, transfer, withdraw).
    run_3tx_scenario()?;

    println!(
        "[xtask] nova-fast complete in {:.1}s. Teardown via `cargo xtask down`.",
        total_start.elapsed().as_secs_f64()
    );
    Ok(())
}

fn spawn_host_bin(name: &str) -> Result<Child> {
    let bin = bin_path(name);
    println!("[xtask] Starting {} on host (binary: {})…", name, bin.display());
    let child = Command::new(bin)
        .env("NF4_RUN_MODE", "local")
        .env("NF4_MOCK_PROVER", "false")
        .env("NF4_FAST_FAIL_NOVA", "1")
        .env("NF4_NIGHTFALL_PROPOSER__DB_URL", MONGO_URL)
        .env("NF4_NIGHTFALL_CLIENT__DB_URL", MONGO_URL)
        .env("NF4_NIGHTFALL_PROPOSER__URL", PROPOSER_URL)
        .env("NF4_NIGHTFALL_CLIENT__URL", CLIENT_URL)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn {name}"))?;
    Ok(child)
}

fn bin_path(name: &str) -> PathBuf {
    PathBuf::from(format!("target/release/{name}"))
}

fn wait_for_http(url: &str, timeout: Duration) -> Result<()> {
    println!("[xtask] Waiting for {url} (timeout: {}s)…", timeout.as_secs());
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(out) = Command::new("curl").args(["-fsS", url]).output() {
            if out.status.success() {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("{url} did not become ready within {:?}", timeout);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn deploy_contracts() -> Result<()> {
    println!("[xtask] Deploying contracts via forge script…");
    let status = Command::new("forge")
        .args([
            "script",
            "blockchain_assets/script/deployer.s.sol:Deployer",
            "--rpc-url",
            ANVIL_RPC_URL,
            "--broadcast",
            "--slow",
        ])
        .env("NF4_RUN_MODE", "local")
        .status()
        .context("failed to invoke forge")?;
    if !status.success() {
        bail!("forge script failed: {status}");
    }
    Ok(())
}

fn run_3tx_scenario() -> Result<()> {
    println!("[xtask] Running 3-tx scenario (deposit / transfer / withdraw)…");
    // Real implementation lives in the live nightfall_test crate; for
    // now we just hit /v1/health on both and print a TODO banner so
    // the developer can use the existing `menu` binary interactively.
    let health_p = format!("{PROPOSER_URL}/v1/health");
    let health_c = format!("{CLIENT_URL}/v1/health");
    let out_p = Command::new("curl").args(["-fsS", &health_p]).output()?;
    let out_c = Command::new("curl").args(["-fsS", &health_c]).output()?;
    if !out_p.status.success() || !out_c.status.success() {
        bail!("proposer or client /v1/health check failed");
    }
    println!("[xtask] Both proposer and client are healthy.");
    println!("[xtask] To drive the 3-tx scenario interactively, run in another shell:");
    println!("        NF4_RUN_MODE=local cargo run --release --features nova-v1 --bin menu");
    println!("[xtask] (or extend this xtask to POST /v1/deposit, /v1/transfer, /v1/withdraw directly).");
    Ok(())
}

fn down() -> Result<()> {
    println!("[xtask] Killing proposer / client processes on the host…");
    for name in [PROPOSER_BIN, CLIENT_BIN] {
        let status = Command::new("pkill")
            .args(["-f", &format!("target/release/{name}")])
            .status();
        match status {
            Ok(s) if s.success() => println!("[xtask] Killed {name}."),
            Ok(_) => println!("[xtask] No {name} processes running."),
            Err(e) => println!("[xtask] pkill failed: {e}"),
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn path_exists(p: &Path) -> bool {
    p.exists()
}
