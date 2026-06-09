use configuration::{logging::init_logging, settings::get_settings};
use lib::plonk_prover::plonk_proof::{PlonkProof, PlonkProvingEngine};
use log::{error, info};
use nightfall_bindings::artifacts::Nightfall;
use nightfall_proposer::drivers::blockchain::event_listener_manager::ensure_running;
use nightfall_proposer::{
    driven::{db::mongo_db::DB, mock_prover::MockProver, rollup_prover::RollupProver},
    drivers::{blockchain::block_assembly::start_block_assembly, rest::routes},
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let settings = get_settings();

    init_logging(
        settings.nightfall_proposer.log_level.as_str(),
        settings.log_app_only,
    );

    // drop any existing database
    let db_url = &settings.nightfall_proposer.db_url;
    info!("Dropping database: {DB}");
    let _ = lib::utils::drop_database(db_url, DB).await;

    let active_id = nightfall_proposer::driven::proving::map_config_to_id(
        &settings.nightfall_proposer.proving_system.active,
    );

    // Validate that the requested active proving system is in fact
    // registered / available BEFORE we start any subsystem. The
    // previous behaviour was to silently fall back to PlonkV1 when
    // the `enabled` list was empty; this caught operators out when
    // they had set `active = NovaV1` but forgotten to add it to
    // `enabled`. We now fail loudly here.
    let registry = nightfall_proposer::driven::proving::build_registry_from_config(&settings)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to build proving-system registry: {e}. \
                 Check [proving_system] in nightfall.toml: \
                 `active` must be present in `enabled` and the corresponding feature must be compiled in."
            );
        });
    let registered_ids = registry.registered_ids();
    info!("Proving-system registry: active = {active_id}, registered = {registered_ids:?}");
    if !registry.is_registered(active_id) {
        panic!(
            "Active proving system {active_id} is not registered (registered: {registered_ids:?}). \
             Set proving_system.enabled = [{active_id}] in nightfall.toml or pick a different active system."
        );
    }

    match active_id {
        lib::proving::ProofSystemId::PlonkV1 => {
            type P = PlonkProof;
            type E = PlonkProvingEngine;
            type N = Nightfall::NightfallCalls;

            let task_0 = if settings.mock_prover {
                info!("Using MockProver");
                tokio::spawn(start_block_assembly::<P, MockProver, N>())
            } else {
                info!("Using RollupProver");
                tokio::spawn(start_block_assembly::<P, RollupProver, N>())
            };

            ensure_running::<P, E, N>().await;
            let routes = routes::<P, E>();
            let task_2 = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
            info!("Starting warp server, block assembler and event_handler threads for PlonkV1");
            let (_r0, _r2) = (task_0.await??, task_2.await?);
        }
        lib::proving::ProofSystemId::NovaV1 => {
            #[cfg(feature = "nova-v1")]
            {
                type P = lib::proving::nova_v1::proof::NovaClientProof;
                type E = lib::proving::nova_v1::client_engine::NovaClientEngine;
                type R = lib::proving::nova_v1::rollup_engine::NovaRollupEngine;
                type N = Nightfall::NightfallCalls;

                if settings.mock_prover {
                    panic!("MockProver is not supported for NovaV1");
                }

                // Read the off-chain `nova_max_steps` and surface a loud
                // warning if it drifts from the on-chain constant
                // (NovaRollupVerifier::MAX_STEPS). The two MUST agree.
                let configured_max = settings.nightfall_proposer.nova_max_steps;
                let default_max = <R as Default>::default().max_steps();
                if configured_max != default_max {
                    log::warn!(
                        "nightfall_proposer.nova_max_steps ({configured_max}) differs from \
                         NovaRollupEngine::DEFAULT_MAX_STEPS ({default_max}). Off-chain will \
                         reject blocks the on-chain verifier would accept (or vice versa). \
                         The on-chain MAX_STEPS is fixed at 10_000 in NovaRollupVerifier.sol; \
                         update the setting or the contract so they match."
                    );
                }
                info!(
                    "Using NovaRollupEngine with nova_max_steps = {configured_max} \
                     (on-chain MAX_STEPS = {})",
                    default_max
                );

                let key_manager = lib::proving::nova_v1::keys::NovaKeyManager::with_default_dir();
                std::fs::create_dir_all(key_manager.key_dir())?;
                info!(
                    "Using Nova key cache directory: {}",
                    key_manager.key_dir().display()
                );

                // Start the REST server FIRST so Docker healthchecks pass
                // immediately. Nova key warmup (especially bincode-deserializing
                // the large PublicParams blob) can take many minutes under
                // emulation, and we must not let it compete with block-assembly
                // CPU on the same physical cores.
                info!("Using NovaRollupEngine");
                ensure_running::<P, E, N>().await;
                let routes = routes::<P, E>();
                let task_2 = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
                info!(
                    "Starting warp server for NovaV1 (block assembly will start after key warmup)"
                );

                // Warm Nova keys to completion before block assembly is allowed
                // to start. This prevents the heavy bincode::deserialize of
                // PublicParams from CPU-starving the proposer's hot path.
                info!("[nova startup] Loading/generating Nova keys (block assembly is gated on this)...");
                let warm_start = std::time::Instant::now();
                tokio::task::spawn_blocking(lib::proving::nova_v1::keys::pregenerate_nova_keys)
                    .await
                    .expect("Nova key warmup task panicked")
                    .expect("Nova key warmup failed");
                info!(
                    "[nova startup] Nova keys ready in {:.2}s; starting block assembly",
                    warm_start.elapsed().as_secs_f64()
                );

                let task_0 = tokio::spawn(start_block_assembly::<P, R, N>());
                info!("Starting block assembler and event_handler threads for NovaV1");
                let (_r0, _r2) = (task_0.await??, task_2.await?);
            }
            #[cfg(not(feature = "nova-v1"))]
            {
                panic!("NovaV1 proving system selected but 'nova-v1' feature is not enabled");
            }
        }
        lib::proving::ProofSystemId::UltraHonkV1 => {
            #[cfg(feature = "ultra-honk-v1")]
            {
                type P = lib::proving::ultrahonk_v1::UltraHonkProof;
                type E = lib::proving::ultrahonk_v1::UltraHonkClientEngine;
                type R = lib::proving::nova_v1::rollup_engine::NovaRollupEngine;
                type N = Nightfall::NightfallCalls;

                if settings.mock_prover {
                    panic!("MockProver is not supported for UltraHonkV1");
                }

                let configured_max = settings.nightfall_proposer.nova_max_steps;
                let default_max = <R as Default>::default().max_steps();
                if configured_max != default_max {
                    log::warn!(
                        "nightfall_proposer.nova_max_steps ({configured_max}) differs from \
                         NovaRollupEngine::DEFAULT_MAX_STEPS ({default_max}). Off-chain will \
                         reject blocks the on-chain verifier would accept (or vice versa). \
                         The on-chain MAX_STEPS is fixed at 10_000 in NovaRollupVerifier.sol; \
                         update the setting or the contract so they match."
                    );
                }
                info!(
                    "Using NovaRollupEngine with ultra-honk-v1 client proofs and nova_max_steps = {configured_max} \
                     (on-chain MAX_STEPS = {})",
                    default_max
                );

                let key_manager = lib::proving::nova_v1::keys::NovaKeyManager::with_default_dir();
                std::fs::create_dir_all(key_manager.key_dir())?;
                info!(
                    "Using Nova key cache directory: {}",
                    key_manager.key_dir().display()
                );

                info!("Using UltraHonkClientEngine with NovaRollupEngine");
                ensure_running::<P, E, N>().await;
                let routes = routes::<P, E>();
                let task_2 = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
                info!(
                    "Starting warp server for UltraHonkV1 (block assembly will start after Nova key warmup)"
                );

                info!("[nova startup] Loading/generating Nova keys (block assembly is gated on this)...");
                let warm_start = std::time::Instant::now();
                tokio::task::spawn_blocking(lib::proving::nova_v1::keys::pregenerate_nova_keys)
                    .await
                    .expect("Nova key warmup task panicked")
                    .expect("Nova key warmup failed");
                info!(
                    "[nova startup] Nova keys ready in {:.2}s; starting block assembly",
                    warm_start.elapsed().as_secs_f64()
                );

                let task_0 = tokio::spawn(start_block_assembly::<P, R, N>());
                info!("Starting block assembler and event_handler threads for UltraHonkV1");
                let (_r0, _r2) = (task_0.await??, task_2.await?);
            }
            #[cfg(not(feature = "ultra-honk-v1"))]
            {
                panic!("UltraHonkV1 selected but 'ultra-honk-v1' feature not enabled");
            }
        }
        _ => panic!("Unsupported proving system"),
    }

    error!("Proposer exited unexpectedly. See information above.");
    Ok(())
}
