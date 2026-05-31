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

    let active_id = nightfall_proposer::driven::proving::map_config_to_id(&settings.nightfall_proposer.proving_system.active);

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
                let key_manager = lib::proving::nova_v1::keys::NovaKeyManager::with_default_dir();
                std::fs::create_dir_all(key_manager.key_dir())?;
                info!(
                    "Using Nova key cache directory: {}",
                    key_manager.key_dir().display()
                );

                info!("Using NovaRollupEngine");
                let task_0 = tokio::spawn(start_block_assembly::<P, R, N>());

                ensure_running::<P, E, N>().await;
                let routes = routes::<P, E>();
                let task_2 = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
                info!("Starting warp server, block assembler and event_handler threads for NovaV1");
                let (_r0, _r2) = (task_0.await??, task_2.await?);
            }
            #[cfg(not(feature = "nova-v1"))]
            {
                panic!("NovaV1 proving system selected but 'nova-v1' feature is not enabled");
            }
        }
        _ => panic!("Unsupported proving system"),
    }

    error!("Proposer exited unexpectedly. See information above.");
    Ok(())
}
