use crate::{
    domain::error::ProposerRejection,
    driven::nightfall_client_transaction::process_nightfall_client_transaction,
    initialisation::get_db_connection, ports::db::TransactionsDB,
};
use ark_bn254::Fr as Fr254;
use futures::Future;
use lib::client_models::{ProposerSwapCancelRequest, SwapCancelResponse};
use lib::hex_conversion::HexConvertible;
use lib::{
    nf_client_proof::{Proof, ProvingEngine},
    shared_entities::ClientTransaction,
};
use log::{error, info};
use warp::{hyper::StatusCode, path, Filter};

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

pub fn cancel_swap_request<P>(
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
where
    P: Proof,
{
    path!("v1" / "swap" / "cancel-request")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handle_cancel_swap_request::<P>)
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

async fn handle_cancel_swap_request<P>(
    request: ProposerSwapCancelRequest,
) -> Result<impl warp::Reply, warp::Rejection>
where
    P: Proof,
{
    let swap_link = Fr254::from_hex_string(&request.swap_link)
        .map_err(|_| warp::reject::custom(ProposerRejection::ClientTransactionFailed))?;
    let db = get_db_connection().await;

    let cancelled =
        <mongodb::Client as TransactionsDB<P>>::cancel_mempool_swap_transactions(db, &swap_link)
            .await
            .ok_or_else(|| warp::reject::custom(ProposerRejection::ClientTransactionFailed))?;

    let response = if cancelled > 0 {
        SwapCancelResponse {
            status: "accepted".to_string(),
            message:
                "Swap cancel request accepted; matching mempool swap legs were marked cancelled"
                    .to_string(),
            matched: cancelled as usize,
        }
    } else {
        let selected = <mongodb::Client as TransactionsDB<P>>::count_selected_swap_transactions(
            db, &swap_link,
        )
        .await
        .map_err(|_| warp::reject::custom(ProposerRejection::ClientTransactionFailed))?;
        let cancelled = <mongodb::Client as TransactionsDB<P>>::count_cancelled_swap_transactions(
            db, &swap_link,
        )
        .await
        .map_err(|_| warp::reject::custom(ProposerRejection::ClientTransactionFailed))?;

        if selected > 0 {
            SwapCancelResponse {
                status: "too_late".to_string(),
                message:
                    "Swap is no longer in proposer mempool and may already be selected for a block"
                        .to_string(),
                matched: 0,
            }
        } else if cancelled > 0 {
            SwapCancelResponse {
                status: "already_cancelled".to_string(),
                message: "Matching swap legs were already cancelled in proposer state"
                    .to_string(),
                matched: cancelled as usize,
            }
        } else {
            SwapCancelResponse {
                status: "not_found".to_string(),
                message: "No matching mempool swap was found for cancellation".to_string(),
                matched: 0,
            }
        }
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&response),
        StatusCode::OK,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::rest::handle_rejection;
    use alloy::primitives::Bytes;
    use ark_bn254::Fr as Fr254;
    use ark_serialize::SerializationError;
    use lib::{
        client_models::ProposerSwapCancelRequest,
        nf_client_proof::ProvingEngine,
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

    #[tokio::test]
    async fn test_cancel_swap_route_rejects_invalid_payload_shape() {
        let filter = cancel_swap_request::<MockProof>().recover(handle_rejection);
        let res = warp::test::request()
            .method("POST")
            .path("/v1/swap/cancel-request")
            .header("content-type", "application/json")
            .body("{}")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cancel_swap_route_rejects_invalid_swap_link_hex() {
        let filter = path!("v1" / "swap" / "cancel-request")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|request: ProposerSwapCancelRequest| async move {
                let parsed = Fr254::from_hex_string(&request.swap_link).map_err(|_| {
                    warp::reject::custom(ProposerRejection::ClientTransactionFailed)
                })?;
                Ok::<_, warp::Rejection>(warp::reply::json(
                    &serde_json::json!({ "swapLink": parsed.to_string() }),
                ))
            })
            .recover(handle_rejection);

        let res = warp::test::request()
            .method("POST")
            .path("/v1/swap/cancel-request")
            .json(&ProposerSwapCancelRequest {
                swap_link: "not-hex".to_string(),
            })
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
