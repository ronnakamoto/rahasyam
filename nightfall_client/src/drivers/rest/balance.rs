use crate::{
    domain::error::ClientRejection, initialisation::get_db_connection, ports::db::CommitmentDB,
};
use alloy::primitives::U256;
use ark_ff::{BigInteger, PrimeField};
use lib::{
    blockchain_client::BlockchainClientConnection, get_fee_token_id,
    hex_conversion::HexConvertible, initialisation::get_blockchain_client_connection,
    nf_token_id::to_nf_token_id_from_str,
};
use std::future::Future;
use std::pin::Pin;
use warp::{http::StatusCode, path, reply::Reply, Filter};

fn encode_balance_hex(balance: ark_bn254::Fr) -> String {
    let encoded = hex::encode(balance.into_bigint().to_bytes_be());
    if encoded.is_empty() || encoded.chars().all(|ch| ch == '0') {
        "00".to_string()
    } else {
        encoded
    }
}
/// Endpoint to get a token balance
/// NB for consistency with the rest of the API,
/// the value is returned as a *hex* string.
pub fn get_balance() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
{
    path!("v1" / "balance" / String / String)
        .and(warp::get())
        .and_then(handle_get_balance)
}

pub async fn handle_get_balance(
    erc_address: String,
    token_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let nf_token_id = to_nf_token_id_from_str(&erc_address, &token_id);
    if let Ok(nf_token_id) = nf_token_id {
        let db = get_db_connection().await;
        let balance = db.get_balance(&nf_token_id).await;
        if let Some(balance) = balance {
            Ok(warp::reply::with_status(
                encode_balance_hex(balance),
                StatusCode::OK,
            ))
        } else {
            Err(warp::reject::custom(ClientRejection::NoSuchToken))
        }
    } else {
        Err(warp::reject::custom(ClientRejection::InvalidTokenId))
    }
}

/// Endpoint to get a fee balance
/// the value is returned as a *hex* string.
pub fn get_fee_balance(
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    path!("v1" / "fee_balance")
        .and(warp::get())
        .and_then(handle_get_fee_balance)
}

pub async fn handle_get_fee_balance() -> Result<impl Reply, warp::Rejection> {
    handle_get_fee_balance_with(current_fee_balance_fetcher()).await
}

/// Endpoint to get the L1 balance of the client's wallet
/// Returns the value as a *hex* string.
pub fn get_l1_balance(
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    path!("v1" / "l1_balance")
        .and(warp::get())
        .and_then(handle_get_l1_balance)
}

type L1BalanceFuture = Pin<Box<dyn Future<Output = Option<U256>> + Send>>;
type L1BalanceFetcher = fn() -> L1BalanceFuture;
type FeeBalanceFuture = Pin<Box<dyn Future<Output = Option<ark_bn254::Fr>> + Send>>;
type FeeBalanceFetcher = fn() -> FeeBalanceFuture;

fn default_fee_balance_fetcher() -> FeeBalanceFuture {
    Box::pin(async {
        // Get the fee token ID from the configured contract addresses and load its balance from the DB.
        let fee_token_id = get_fee_token_id();
        let db = get_db_connection().await;
        db.get_balance(&fee_token_id).await
    })
}

#[cfg(test)]
fn current_fee_balance_fetcher() -> FeeBalanceFetcher {
    let override_fetcher = test_support::get_fee_balance_fetcher_override()
        .lock()
        .expect("test fetcher lock should not be poisoned")
        .as_ref()
        .copied();
    override_fetcher.unwrap_or(default_fee_balance_fetcher as FeeBalanceFetcher)
}

#[cfg(not(test))]
fn current_fee_balance_fetcher() -> FeeBalanceFetcher {
    default_fee_balance_fetcher
}

fn default_l1_balance_fetcher() -> L1BalanceFuture {
    Box::pin(async {
        let client = get_blockchain_client_connection().await.read().await;
        client.get_balance().await
    })
}

#[cfg(test)]
fn current_l1_balance_fetcher() -> L1BalanceFetcher {
    let override_fetcher = test_support::get_l1_balance_fetcher_override()
        .lock()
        .expect("test fetcher lock should not be poisoned")
        .as_ref()
        .copied();
    override_fetcher.unwrap_or(default_l1_balance_fetcher as L1BalanceFetcher)
}

#[cfg(not(test))]
fn current_l1_balance_fetcher() -> L1BalanceFetcher {
    default_l1_balance_fetcher
}

async fn handle_get_l1_balance_with<F, Fut>(fetch_balance: F) -> Result<impl Reply, warp::Rejection>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<U256>>,
{
    match fetch_balance().await {
        Some(balance) => Ok(warp::reply::with_status(
            balance.to_hex_string(),
            StatusCode::OK,
        )),
        None => Err(warp::reject::custom(ClientRejection::NoSuchToken)),
    }
}

async fn handle_get_fee_balance_with<F, Fut>(fetch_balance: F) -> Result<impl Reply, warp::Rejection>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<ark_bn254::Fr>>,
{
    match fetch_balance().await {
        Some(balance) => Ok(warp::reply::with_status(
            encode_balance_hex(balance),
            StatusCode::OK,
        )),
        None => Err(warp::reject::custom(ClientRejection::NoSuchToken)),
    }
}

pub async fn handle_get_l1_balance() -> Result<impl Reply, warp::Rejection> {
    // Read the current wallet balance from the shared blockchain client.
    handle_get_l1_balance_with(current_l1_balance_fetcher()).await
}

#[cfg(test)]
mod test_support {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static L1_BALANCE_FETCHER_OVERRIDE: OnceLock<Mutex<Option<L1BalanceFetcher>>> = OnceLock::new();
    static FEE_BALANCE_FETCHER_OVERRIDE: OnceLock<Mutex<Option<FeeBalanceFetcher>>> = OnceLock::new();
    static L1_BALANCE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static FEE_BALANCE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(super) fn get_l1_balance_fetcher_override() -> &'static Mutex<Option<L1BalanceFetcher>> {
        L1_BALANCE_FETCHER_OVERRIDE.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn get_fee_balance_fetcher_override() -> &'static Mutex<Option<FeeBalanceFetcher>> {
        FEE_BALANCE_FETCHER_OVERRIDE.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn get_l1_balance_test_lock() -> &'static Mutex<()> {
        L1_BALANCE_TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    pub(super) fn get_fee_balance_test_lock() -> &'static Mutex<()> {
        FEE_BALANCE_TEST_LOCK.get_or_init(|| Mutex::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::hyper::body::to_bytes;
    use warp::{http::StatusCode, Reply};

    fn fetch_some_balance() -> L1BalanceFuture {
        Box::pin(async { Some(U256::from(0x123u64)) })
    }

    fn fetch_no_balance() -> L1BalanceFuture {
        Box::pin(async { None })
    }

    fn fetch_some_fee_balance() -> FeeBalanceFuture {
        Box::pin(async { Some(ark_bn254::Fr::from(3u64)) })
    }

    fn fetch_no_fee_balance() -> FeeBalanceFuture {
        Box::pin(async { None })
    }

    #[tokio::test]
    async fn test_handle_l1_balance_returns_hex_balance() {
        let _guard = test_support::get_l1_balance_test_lock()
            .lock()
            .expect("test lock should not be poisoned");
        *test_support::get_l1_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = Some(fetch_some_balance);

        let res = handle_get_l1_balance().await;
        let response = res.unwrap().into_response();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            U256::from(0x123u64).to_hex_string()
        );

        *test_support::get_l1_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = None;
    }

    #[tokio::test]
    async fn test_handle_l1_balance_returns_not_found_when_balance_unavailable() {
        let _guard = test_support::get_l1_balance_test_lock()
            .lock()
            .expect("test lock should not be poisoned");
        *test_support::get_l1_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = Some(fetch_no_balance);

        let err = match handle_get_l1_balance().await {
            Ok(_) => panic!("missing balance should return a rejection"),
            Err(err) => err,
        };
        let response = super::super::handle_rejection(err)
            .await
            .unwrap()
            .into_response();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "No such token"
        );

        *test_support::get_l1_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = None;
    }

    #[tokio::test]
    async fn test_handle_fee_balance_returns_hex_balance() {
        let _guard = test_support::get_fee_balance_test_lock()
            .lock()
            .expect("test lock should not be poisoned");
        *test_support::get_fee_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = Some(fetch_some_fee_balance);

        let res = handle_get_fee_balance().await;
        let response = res.unwrap().into_response();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            ark_bn254::Fr::from(3u64).to_hex_string()
        );

        *test_support::get_fee_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = None;
    }

    #[tokio::test]
    async fn test_handle_fee_balance_returns_not_found_when_balance_unavailable() {
        let _guard = test_support::get_fee_balance_test_lock()
            .lock()
            .expect("test lock should not be poisoned");
        *test_support::get_fee_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = Some(fetch_no_fee_balance);

        let err = match handle_get_fee_balance().await {
            Ok(_) => panic!("missing fee balance should return a rejection"),
            Err(err) => err,
        };
        let response = super::super::handle_rejection(err)
            .await
            .unwrap()
            .into_response();
        let status = response.status();
        let body = to_bytes(response.into_body()).await.unwrap();

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(std::str::from_utf8(&body).unwrap(), "No such token");

        *test_support::get_fee_balance_fetcher_override()
            .lock()
            .expect("test fetcher lock should not be poisoned") = None;
    }
}
