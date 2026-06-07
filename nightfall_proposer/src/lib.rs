pub mod domain;
pub mod driven;
pub mod drivers;
pub mod ports;
pub mod services;

use ark_bn254::Fr as Fr254;
use jf_primitives::{poseidon::Poseidon, trees::timber::Timber};
use std::sync::{OnceLock, RwLock};

/// Resolve the effective `max_event_listener_attempts` for the proposer.
///
/// Setting `NF4_FAST_FAIL_NOVA=1` (any non-empty value) collapses the
/// retry budget to **1** so a regression in the event-listener / block-assembly
/// loop surfaces in seconds instead of the default ~5-minute exponential
/// backoff. This is the iteration-mode override; default behaviour is
/// unchanged.
pub fn effective_event_listener_attempts(configured: Option<u32>) -> u32 {
    if std::env::var("NF4_FAST_FAIL_NOVA").is_ok() {
        log::warn!(
            "NF4_FAST_FAIL_NOVA is set: collapsing event-listener max_attempts to 1 \
             (configured was {:?}). Set to 0 to disable.",
            configured
        );
        1
    } else {
        configured.unwrap_or(10)
    }
}

type AppendOnlyTree = Timber<Fr254, Poseidon<Fr254>>;

/// This function is used so that we can work with one historic root tree across the entire application.
pub fn get_historic_root_tree() -> &'static RwLock<AppendOnlyTree> {
    static ROOT_TREE: OnceLock<RwLock<AppendOnlyTree>> = OnceLock::new();
    ROOT_TREE.get_or_init(|| {
        let mut tree = Timber::new(Poseidon::<Fr254>::new(), 32);
        tree.insert_leaf(Fr254::from(0u8))
            .expect("Couldn't insert zero leaf into the tree");
        RwLock::new(tree)
    })
}

pub mod initialisation {

    use super::driven::block_assembler::SmartTrigger;
    use crate::{
        driven::block_assembler::BlockAssemblyStatus,
        ports::{
            block_assembly_trigger::BlockAssemblyTrigger,
            trees::{CommitmentTree, HistoricRootTree, NullifierTree},
        },
    };
    use ark_bn254::Fr as Fr254;
    use ark_std::sync::Arc;
    use configuration::settings::get_settings;
    use lib::{
        blockchain_client::BlockchainClientConnection, nf_client_proof::Proof,
        wallets::LocalWsClient,
    };
    use mongodb::Client;
    use tokio::sync::{OnceCell, RwLock};

    /// This function is used to provide a singleton database connection across the entire application.
    pub async fn get_db_connection() -> &'static Client {
        static DB_CONNECTION: OnceCell<Client> = OnceCell::const_new();
        DB_CONNECTION
            .get_or_init(|| async {
                // select the proposer to use
                let uri = &get_settings().nightfall_proposer.db_url;
                let client = Client::with_uri_str(uri)
                    .await
                    .expect("Could not create database connection");
                // Use the correct tree dimensions for the active proving system.
                // Nova uses sub_tree_height=0 (capacity=1 per insert), Plonk uses 3 (capacity=8).
                let is_nova = get_settings().nightfall_proposer.proving_system.active
                    == configuration::settings::ProvingSystemIdConfig::NovaV1;
                let (tree_height, sub_tree_height) = if is_nova { (32, 0) } else { (29, 3) };
                <mongodb::Client as CommitmentTree<Fr254>>::new_commitment_tree(
                    &client,
                    tree_height,
                    sub_tree_height,
                )
                .await
                .expect("Could not create commitment tree");
                <mongodb::Client as HistoricRootTree<Fr254>>::new_historic_root_tree(&client, 32)
                    .await
                    .expect("Could not create historic root tree");
                <mongodb::Client as NullifierTree<Fr254>>::new_nullifier_tree(
                    &client,
                    tree_height,
                    sub_tree_height,
                )
                .await
                .expect("Could not create nullifier tree");

                <Client as HistoricRootTree<Fr254>>::append_historic_commitment_root(
                    &client,
                    &Fr254::from(0u8),
                    true,
                )
                .await
                .expect("Couldn't insert zero leaf into the historic root tree");
                client
            })
            .await
    }

    /// This function is used to provide a singleton blockchain client connection across the entire application.
    pub async fn get_blockchain_client_connection() -> &'static RwLock<LocalWsClient> {
        static BLOCKCHAIN_CLIENT_CONNECTION: OnceCell<RwLock<LocalWsClient>> =
            OnceCell::const_new();
        BLOCKCHAIN_CLIENT_CONNECTION
            .get_or_init(|| async {
                RwLock::new(
                    LocalWsClient::try_from_settings(get_settings())
                        .await
                        .expect("Could not create blockchain client connection"),
                )
            })
            .await
    }

    /// This function is used to provide a singleton trigger for block assembly across the entire application.
    pub async fn get_block_assembly_trigger<P: Proof>(
    ) -> &'static Arc<RwLock<dyn BlockAssemblyTrigger + Send + Sync>> {
        static BLOCK_ASSEMBLY_TRIGGER: OnceCell<
            Arc<RwLock<dyn BlockAssemblyTrigger + Send + Sync>>,
        > = OnceCell::const_new();
        BLOCK_ASSEMBLY_TRIGGER
            .get_or_init(|| async {
                let status = get_block_assembly_status().await;
                let db_client = get_db_connection().await;
                let settings = get_settings();
                let initial_interval_secs = settings
                    .nightfall_proposer
                    .block_assembly_initial_interval_secs;
                let max_wait_secs = settings.nightfall_proposer.block_assembly_max_wait_secs;
                let target_fill_ratio =
                    settings.nightfall_proposer.block_assembly_target_fill_ratio as f32;

                let smart_trigger = SmartTrigger::<P>::new(
                    initial_interval_secs,
                    max_wait_secs,
                    status,
                    db_client,
                    target_fill_ratio,
                );
                Arc::new(RwLock::new(smart_trigger))
                    as Arc<RwLock<dyn BlockAssemblyTrigger + Send + Sync>>
            })
            .await
    }

    /// This function is used to provide a singleton status for the BlockAssemblyTrigger across the entire application.
    pub async fn get_block_assembly_status() -> &'static RwLock<BlockAssemblyStatus> {
        static BLOCK_ASSEMBLY_STATUS: OnceCell<RwLock<BlockAssemblyStatus>> = OnceCell::const_new();
        BLOCK_ASSEMBLY_STATUS
            .get_or_init(|| async { RwLock::new(BlockAssemblyStatus::new()) })
            .await
    }
}
