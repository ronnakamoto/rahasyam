use ark_bn254::Fr as Fr254;
use configuration::{
    logging::init_logging,
    settings::{get_settings, ProvingSystemIdConfig},
};
use lib::{
    merkle_trees::trees::TreeMetadata,
    plonk_prover::plonk_proof::{PlonkProof, PlonkProvingEngine},
    shared_entities::Node,
    utils,
};
use log::{error, info};
use nightfall_bindings::artifacts::Nightfall;
use nightfall_client::{
    domain::entities::Request,
    driven::queue::process_queue,
    drivers::{blockchain::event_listener_manager::ensure_running, rest::routes},
};
use tokio::task::JoinError;

// ── Global allocator: jemalloc ────────────────────────────────────────────
// The default glibc allocator fragments badly under the Plonk recursive
// prover's pattern of "allocate a few hundred MB of field elements, do
// parallel FFT on them, drop, repeat". jemalloc's per-size-class binning
// reuses the same pages across iterations and keeps RSS noticeably below
// the high-water mark that we hit with the system allocator (the swap
// proof was being OOM-killed at 8 GiB before this change).
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<(), JoinError> {
    // declare the types of wallet that we're using
    type N = Nightfall::NightfallCalls;
    let settings = get_settings();
    init_logging(
        settings.nightfall_client.log_level.as_str(),
        settings.log_app_only,
    );
    // ── clear desynchronised tree metadata/requests ───────────────────────────
    // drop the commitment merkle tree data because it will be out of date and need resynching. The commitments are retained.
    // status reflected in the DB
    let url = &settings.nightfall_client.db_url;
    utils::drop_collection::<TreeMetadata<Fr254>>(
        url.as_str(),
        "nightfall",
        "commitment_tree_metadata",
    )
    .await
    .expect("Failed to drop Metadata collection");
    utils::drop_collection::<Node<Fr254>>(url.as_str(), "nightfall", "commitment_tree_nodes")
        .await
        .expect("Failed to drop Node collection");
    utils::drop_collection::<Node<Fr254>>(url.as_str(), "nightfall", "commitment_tree_cache")
        .await
        .expect("Failed to drop Cache collection");
    // drop the request-ID tracking collection
    utils::drop_collection::<Request>(url.as_str(), "nightfall", "requests")
        .await
        .expect("Failed to drop Requests collection");

    // We fetch active config from proposer's proving system to determine which system is enabled globally.
    // (A more global config might be better, but this suffices for now).
    let active_id =
        ProvingSystemIdConfig::from_str(settings.nightfall_proposer.proving_system.active.as_str())
            .unwrap_or(ProvingSystemIdConfig::PlonkV1);

    let active_id = match active_id {
        ProvingSystemIdConfig::PlonkV1 => lib::proving::ProofSystemId::PlonkV1,
        ProvingSystemIdConfig::NovaV1 | ProvingSystemIdConfig::NovaBlsV1 => {
            lib::proving::ProofSystemId::NovaV1
        }
    };

    match active_id {
        lib::proving::ProofSystemId::PlonkV1 => {
            type P = PlonkProof;
            type E = PlonkProvingEngine;
            type N = Nightfall::NightfallCalls;

            ensure_running::<N>().await;
            let routes = routes::<P, N>();
            let task_warp = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
            let task_queue = tokio::spawn(process_queue::<P, E, N>());

            info!("Starting warp server and request queue for PlonkV1 (event listener managed separately)");
            let (_r2, _r3) = (task_warp.await?, task_queue.await?);
        }
        lib::proving::ProofSystemId::NovaV1 => {
            #[cfg(feature = "nova-v1")]
            {
                type P = lib::proving::nova_v1::proof::NovaClientProof;
                type E = lib::proving::nova_v1::client_engine::NovaClientEngine;
                type N = Nightfall::NightfallCalls;

                ensure_running::<N>().await;
                let routes = routes::<P, N>();
                let task_warp = tokio::spawn(warp::serve(routes).run(([0, 0, 0, 0], 3000)));
                let task_queue = tokio::spawn(process_queue::<P, E, N>());

                info!("Starting warp server and request queue for NovaV1 (event listener managed separately)");
                let (_r2, _r3) = (task_warp.await?, task_queue.await?);
            }
            #[cfg(not(feature = "nova-v1"))]
            {
                panic!("NovaV1 proving system selected but 'nova-v1' feature is not enabled");
            }
        }
        _ => panic!("Unsupported proving system"),
    }

    error!("Client exited unexpectedly.");
    Ok(())
}
