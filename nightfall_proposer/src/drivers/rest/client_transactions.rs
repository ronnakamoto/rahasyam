use crate::{
    domain::{entities::ClientTransactionWithMetaData, error::ProposerRejection},
    driven::nightfall_client_transaction::process_nightfall_client_transaction,
    initialisation::get_db_connection,
    ports::db::TransactionsDB,
};
use ark_bn254::Fr as Fr254;
use futures::Future;
use lib::{
    client_models::CancelSwapRequest,
    hex_conversion::HexConvertible,
    nf_client_proof::{Proof, ProvingEngine},
    shared_entities::ClientTransaction,
};
use log::{error, info};
use serde::Serialize;
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
        .and(warp::body::json())
        .and_then(|request| handle_cancel_swap::<P>(request))
}

#[derive(Serialize)]
struct CancelSwapResponse {
    removed: u64,
    already_absent: bool,
}

fn matching_swaps_from_mempool<P>(
    mempool_transactions: Option<Vec<(Vec<u32>, ClientTransactionWithMetaData<P>)>>,
    swap_link: Fr254,
) -> Result<Vec<ClientTransactionWithMetaData<P>>, ProposerRejection>
where
    P: Proof,
{
    let mempool_transactions = mempool_transactions.ok_or(ProposerRejection::FailedToCancelSwap)?;

    Ok(mempool_transactions
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

    let db = get_db_connection().await;
    let matching_swaps = matching_swaps_from_mempool(
        <mongodb::Client as TransactionsDB<P>>::get_all_mempool_client_transactions(db).await,
        swap_link,
    )
    .map_err(warp::reject::custom)?;

    if matching_swaps.is_empty() {
        return Ok(warp::reply::with_status(
            json(&CancelSwapResponse {
                removed: 0,
                already_absent: true,
            }),
            StatusCode::OK,
        ));
    }

    let removed =
        <mongodb::Client as TransactionsDB<P>>::set_in_mempool(db, &matching_swaps, false)
            .await
            .ok_or_else(|| warp::reject::custom(ProposerRejection::FailedToCancelSwap))?;

    if removed != matching_swaps.len() as u64 {
        error!(
            "Partial swap cancel detected: expected to remove {} mempool entries for swap_link {}, removed {}",
            matching_swaps.len(),
            request.swap_link,
            removed
        );
        return Err(warp::reject::custom(ProposerRejection::FailedToCancelSwap));
    }

    Ok(warp::reply::with_status(
        json(&CancelSwapResponse {
            removed,
            already_absent: false,
        }),
        StatusCode::OK,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::rest::handle_rejection;
    use alloy::primitives::Bytes;
    use ark_serialize::SerializationError;
    use lib::{
        nf_client_proof::ProvingEngine,
        plonk_prover::plonk_proof::PlonkProof,
        shared_entities::{ClientTransaction, CompressedSecrets},
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

        let result = matching_swaps_from_mempool::<PlonkProof>(None, swap_link);

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
            hash: vec![4, 5, 6],
            historic_roots: vec![],
        };

        let result = matching_swaps_from_mempool::<PlonkProof>(
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

        let result = matching_swaps_from_mempool::<PlonkProof>(Some(vec![]), swap_link)
            .expect("empty mempool should not be treated as an error");

        assert!(result.is_empty());
    }
}
