use crate::{
    domain::{entities::ClientTransactionWithMetaData, error::ProposerRejection},
    driven::nightfall_client_transaction::process_nightfall_client_transaction,
    drivers::blockchain::nightfall_event_listener::get_synchronisation_status,
    initialisation::get_db_connection,
    ports::{contracts::NightfallContract, db::TransactionsDB},
    services::selected_transactions::{
        cancel_orphaned_selected_transactions, get_classified_selected_transactions,
        SelectedTransactionState,
    },
};
use ark_bn254::Fr as Fr254;
use futures::Future;
use lib::{
    client_models::{CancelSwapRequest, CancelSwapResponse, CancelSwapStatus},
    hex_conversion::HexConvertible,
    nf_client_proof::{Proof, ProvingEngine},
    shared_entities::ClientTransaction,
};
use log::{error, info};
use nightfall_bindings::artifacts::Nightfall;
use warp::{hyper::StatusCode, path, reply::json, Filter, Reply};

pub fn client_transaction<P, E>(
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
where
    P: Proof,
    E: ProvingEngine<P>,
{
    path!("v1" / "transaction")
        .and(warp::body::json())
        .and_then(|transaction| handle_client_transaction::<P, E>(transaction))
}

pub fn cancel_swap<P>(
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
where
    P: Proof,
{
    path!("v1" / "swap" / "cancel")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|request| handle_cancel_swap::<P>(request))
}

fn matching_swaps_from_transactions<P>(
    transactions: Option<Vec<(Vec<u32>, ClientTransactionWithMetaData<P>)>>,
    swap_link: Fr254,
) -> Result<Vec<ClientTransactionWithMetaData<P>>, ProposerRejection>
where
    P: Proof,
{
    let transactions = transactions.ok_or(ProposerRejection::FailedToCancelSwap)?;

    Ok(transactions
        .into_iter()
        .map(|(_, tx)| tx)
        .filter(|tx| tx.client_transaction.swap_link == swap_link)
        .collect())
}

async fn handle_client_transaction<P, E>(
    transaction: ClientTransaction<P>,
) -> Result<impl warp::Reply, warp::Rejection>
where
    P: Proof,
    E: ProvingEngine<P>,
{
    handle_client_transaction_with(transaction, |transaction| async move {
        let result = process_nightfall_client_transaction::<P, E>(transaction).await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Error processing client transaction: {e}");
                Err(warp::reject::custom(
                    ProposerRejection::ClientTransactionFailed,
                ))
            }
        }
    })
    .await
}

async fn handle_client_transaction_with<P, F, Fut>(
    transaction: ClientTransaction<P>,
    process: F,
) -> Result<impl warp::Reply, warp::Rejection>
where
    P: Proof,
    F: FnOnce(ClientTransaction<P>) -> Fut,
    Fut: Future<Output = Result<(), warp::Rejection>>,
{
    info!("Received client transaction");
    process(transaction).await?;
    Ok(StatusCode::CREATED)
}

async fn handle_cancel_swap<P>(request: CancelSwapRequest) -> Result<impl Reply, warp::Rejection>
where
    P: Proof,
{
    let swap_link = Fr254::from_hex_string(&request.swap_link).map_err(|e| {
        error!("Invalid swap_link supplied for cancellation: {e}");
        warp::reject::custom(ProposerRejection::FailedToCancelSwap)
    })?;

    let current_layer2_block_number = <Nightfall::NightfallCalls as NightfallContract>::get_current_layer2_blocknumber()
        .await
        .map_err(|_| warp::reject::custom(ProposerRejection::FailedToCancelSwap))?
        .try_into()
        .map_err(|_| warp::reject::custom(ProposerRejection::FailedToCancelSwap))?;
    let is_synchronised = get_synchronisation_status()
        .await
        .read()
        .await
        .is_synchronised();

    let db = get_db_connection().await;
    let response = determine_cancel_swap_response::<P>(
        db,
        swap_link,
        current_layer2_block_number,
        is_synchronised,
    )
    .await
    .map_err(warp::reject::custom)?;

    Ok(warp::reply::with_status(
        json(&response),
        StatusCode::OK,
    ))
}

async fn determine_cancel_swap_response<P>(
    db: &mongodb::Client,
    swap_link: Fr254,
    current_layer2_block_number: u64,
    is_synchronised: bool,
) -> Result<CancelSwapResponse, ProposerRejection>
where
    P: Proof,
{
    let matching_swaps = matching_swaps_from_transactions(
        <mongodb::Client as TransactionsDB<P>>::get_all_mempool_client_transactions(db).await,
        swap_link,
    )?;

    if !matching_swaps.is_empty() {
        let removed =
            <mongodb::Client as TransactionsDB<P>>::cancel_mempool_transactions(db, &matching_swaps)
                .await
                .ok_or(ProposerRejection::FailedToCancelSwap)?;

        if removed != matching_swaps.len() as u64 {
            error!(
                "Partial swap cancel detected: expected to remove {} mempool entries for swap_link {}, removed {}",
                matching_swaps.len(),
                swap_link.to_hex_string(),
                removed
            );
            return Err(ProposerRejection::FailedToCancelSwap);
        }

        return Ok(CancelSwapResponse {
            status: CancelSwapStatus::CancelledFromMempool,
            removed,
        });
    }

    let selected_swaps = get_classified_selected_transactions::<P>(
        db,
        current_layer2_block_number,
        is_synchronised,
    )
    .await
    .ok_or(ProposerRejection::FailedToCancelSwap)?;

    if selected_swaps.iter().any(|classified| {
        classified.transaction.client_transaction.swap_link == swap_link
            && classified.state == SelectedTransactionState::Included
    }) {
        return Ok(CancelSwapResponse {
            status: CancelSwapStatus::AlreadyIncluded,
            removed: 0,
        });
    }

    let orphaned_cancelled = cancel_orphaned_selected_transactions::<P>(
        db,
        swap_link,
        current_layer2_block_number,
        is_synchronised,
    )
    .await
    .ok_or(ProposerRejection::FailedToCancelSwap)?;
    if orphaned_cancelled > 0 {
        return Ok(CancelSwapResponse {
            status: CancelSwapStatus::CancelledFromMempool,
            removed: 0,
        });
    }

    if selected_swaps.iter().any(|classified| {
        classified.transaction.client_transaction.swap_link == swap_link
            && classified.state == SelectedTransactionState::InFlight
    }) {
        return Ok(CancelSwapResponse {
            status: CancelSwapStatus::AlreadyAssembled,
            removed: 0,
        });
    }

    let already_cancelled = <mongodb::Client as TransactionsDB<P>>::get_all_transactions(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(_, transaction)| transaction)
        .any(|transaction| {
            transaction.client_transaction.swap_link == swap_link
                && transaction.cancelled_explicitly
        });

    if already_cancelled {
        return Ok(CancelSwapResponse {
            status: CancelSwapStatus::CancelledFromMempool,
            removed: 0,
        });
    }

    Ok(CancelSwapResponse {
        status: CancelSwapStatus::NeverPresent,
        removed: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        driven::db::mongo_db::StoredBlock,
        ports::db::{BlockStorageDB, TransactionsDB},
    };
    use crate::drivers::rest::handle_rejection;
    use alloy::primitives::Bytes;
    use alloy::primitives::Address;
    use ark_serialize::SerializationError;
    use ark_std::Zero;
    use lib::{
        nf_client_proof::ProvingEngine,
        plonk_prover::plonk_proof::PlonkProof,
        shared_entities::{ClientTransaction, CompressedSecrets},
        tests_utils::{get_db_connection, get_mongo},
    };
    use serde::{Deserialize, Serialize};
    use warp::{http::StatusCode, Filter};

    #[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
    struct MockProof {
        a: Vec<u8>,
        b: Vec<u8>,
        c: Vec<u8>,
    }

    #[derive(Debug)]
    struct MockProvingEngine;

    impl Proof for MockProof {
        fn compress_proof(&self) -> Result<Bytes, SerializationError> {
            Ok(Bytes::from_static(b"mock-proof"))
        }

        fn from_compressed(_compressed: Bytes) -> Result<Self, SerializationError> {
            Ok(Self {
                a: vec![1],
                b: vec![2],
                c: vec![3],
            })
        }
    }

    impl ProvingEngine<MockProof> for MockProvingEngine {
        type Error = std::fmt::Error;

        fn prove(
            _private_inputs: &mut lib::nf_client_proof::PrivateInputs,
            _public_inputs: &mut lib::nf_client_proof::PublicInputs,
        ) -> Result<MockProof, Self::Error> {
            Ok(Self::default_proof())
        }

        fn verify(
            _proof: &MockProof,
            _public_inputs: &lib::nf_client_proof::PublicInputs,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    impl MockProvingEngine {
        fn default_proof() -> MockProof {
            MockProof {
                a: vec![1],
                b: vec![2],
                c: vec![3],
            }
        }
    }

    fn sample_transaction() -> ClientTransaction<MockProof> {
        ClientTransaction {
            fee: Fr254::from(2u64),
            historic_commitment_root: Fr254::from(0u64),
            commitments: [
                Fr254::from(10u64),
                Fr254::from(0u64),
                Fr254::from(0u64),
                Fr254::from(0u64),
            ],
            nullifiers: [
                Fr254::from(1u64),
                Fr254::from(0u64),
                Fr254::from(0u64),
                Fr254::from(0u64),
            ],
            compressed_secrets: CompressedSecrets::default(),
            swap_link: Fr254::from(0u64),
            deadline: Fr254::from(0u64),
            swap_side: Fr254::from(0u64),
            proof: MockProvingEngine::default_proof(),
        }
    }

    fn sample_selected_swap_transaction(
        commitment: Fr254,
        swap_link: Fr254,
        block_l2: Option<u64>,
        in_mempool: bool,
        hash: Vec<u32>,
    ) -> ClientTransactionWithMetaData<MockProof> {
        ClientTransactionWithMetaData {
            client_transaction: ClientTransaction {
                fee: Fr254::from(2u64),
                historic_commitment_root: Fr254::from(0u64),
                commitments: [commitment, Fr254::zero(), Fr254::zero(), Fr254::zero()],
                nullifiers: [
                    Fr254::from(1u64),
                    Fr254::from(0u64),
                    Fr254::from(0u64),
                    Fr254::from(0u64),
                ],
                compressed_secrets: CompressedSecrets::default(),
                swap_link,
                deadline: Fr254::from(0u64),
                swap_side: Fr254::from(0u64),
                proof: MockProvingEngine::default_proof(),
            },
            block_l2,
            in_mempool,
            cancelled_explicitly: false,
            hash,
            historic_roots: vec![],
        }
    }

    #[tokio::test]
    async fn test_client_transaction_route_rejects_malformed_json() {
        let filter = client_transaction::<MockProof, MockProvingEngine>();
        let res = warp::test::request()
            .method("POST")
            .path("/v1/transaction")
            .header("content-type", "application/json")
            .body("{")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_client_transaction_route_rejects_invalid_payload_shape() {
        let filter = client_transaction::<MockProof, MockProvingEngine>();
        let res = warp::test::request()
            .method("POST")
            .path("/v1/transaction")
            .header("content-type", "application/json")
            .body("{}")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_client_transaction_route_maps_processing_failure_to_bad_request() {
        let filter = path!("v1" / "transaction")
            .and(warp::body::json())
            .and_then(|transaction: ClientTransaction<MockProof>| async move {
                handle_client_transaction_with(transaction, |_tx| async {
                    Err(warp::reject::custom(
                        ProposerRejection::ClientTransactionFailed,
                    ))
                })
                .await
            })
            .recover(handle_rejection);

        let res = warp::test::request()
            .method("POST")
            .path("/v1/transaction")
            .json(&sample_transaction())
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            std::str::from_utf8(res.body()).unwrap(),
            "Client transaction failed"
        );
    }

    #[test]
    fn cancel_swap_returns_error_when_mempool_read_fails() {
        let swap_link = Fr254::from(7u64);

        let result = matching_swaps_from_transactions::<PlonkProof>(None, swap_link);

        assert!(matches!(result, Err(ProposerRejection::FailedToCancelSwap)));
    }

    #[test]
    fn cancel_swap_filters_matching_swap_link() {
        let swap_link = Fr254::from(7u64);
        let other_swap_link = Fr254::from(8u64);
        let matching_tx = ClientTransactionWithMetaData {
            client_transaction: ClientTransaction {
                swap_link,
                ..Default::default()
            },
            block_l2: None,
            in_mempool: true,
            cancelled_explicitly: false,
            hash: vec![1, 2, 3],
            historic_roots: vec![],
        };
        let other_tx = ClientTransactionWithMetaData {
            client_transaction: ClientTransaction {
                swap_link: other_swap_link,
                ..Default::default()
            },
            block_l2: None,
            in_mempool: true,
            cancelled_explicitly: false,
            hash: vec![4, 5, 6],
            historic_roots: vec![],
        };

        let result = matching_swaps_from_transactions::<PlonkProof>(
            Some(vec![
                (matching_tx.hash.clone(), matching_tx.clone()),
                (other_tx.hash.clone(), other_tx),
            ]),
            swap_link,
        )
        .expect("mempool read should succeed");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hash, matching_tx.hash);
    }

    #[test]
    fn cancel_swap_treats_empty_mempool_as_already_absent_state() {
        let swap_link = Fr254::from(7u64);

        let result = matching_swaps_from_transactions::<PlonkProof>(Some(vec![]), swap_link)
            .expect("empty mempool should not be treated as an error");

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn cancel_swap_returns_already_included_for_selected_tx_present_in_stored_block() {
        let container = get_mongo().await;
        let db = get_db_connection(&container).await;
        let swap_link = Fr254::from(42u64);
        let tx = sample_selected_swap_transaction(
            Fr254::from(10u64),
            swap_link,
            Some(7),
            false,
            vec![4, 2, 0],
        );
        db.store_transaction(tx.clone()).await.unwrap();
        db.store_block(&StoredBlock {
            layer2_block_number: 7,
            commitments: vec![Fr254::from(10u64).to_hex_string()],
            proposer_address: Address::ZERO,
        })
        .await
        .unwrap();

        let response =
            determine_cancel_swap_response::<MockProof>(&db, swap_link, 8, true)
                .await
                .unwrap();

        assert_eq!(response.status, CancelSwapStatus::AlreadyIncluded);
        assert_eq!(response.removed, 0);
    }

    #[tokio::test]
    async fn cancel_swap_terminally_cancels_orphaned_selected_tx_and_is_idempotent() {
        let container = get_mongo().await;
        let db = get_db_connection(&container).await;
        let swap_link = Fr254::from(99u64);
        let tx = sample_selected_swap_transaction(
            Fr254::from(10u64),
            swap_link,
            Some(7),
            false,
            vec![9, 9, 9],
        );
        db.store_transaction(tx.clone()).await.unwrap();

        let first =
            determine_cancel_swap_response::<MockProof>(&db, swap_link, 8, true)
                .await
                .unwrap();
        let stored_after_first: ClientTransactionWithMetaData<MockProof> =
            db.get_transaction(&tx.hash).await.unwrap();
        let second =
            determine_cancel_swap_response::<MockProof>(&db, swap_link, 8, true)
                .await
                .unwrap();

        assert_eq!(first.status, CancelSwapStatus::CancelledFromMempool);
        assert_eq!(first.removed, 0);
        assert!(!stored_after_first.in_mempool);
        assert_eq!(stored_after_first.block_l2, None);
        assert!(stored_after_first.cancelled_explicitly);
        assert_eq!(second.status, CancelSwapStatus::CancelledFromMempool);
        assert_eq!(second.removed, 0);
    }

    #[tokio::test]
    async fn cancel_swap_stays_conservative_while_desynchronised_with_missing_local_block() {
        let container = get_mongo().await;
        let db = get_db_connection(&container).await;
        let swap_link = Fr254::from(123u64);
        let tx = sample_selected_swap_transaction(
            Fr254::from(10u64),
            swap_link,
            Some(30),
            false,
            vec![1, 2, 3, 4],
        );
        db.store_transaction(tx).await.unwrap();

        let response =
            determine_cancel_swap_response::<MockProof>(&db, swap_link, 100, false)
                .await
                .unwrap();

        assert_eq!(response.status, CancelSwapStatus::AlreadyAssembled);
        assert_eq!(response.removed, 0);
    }
}
