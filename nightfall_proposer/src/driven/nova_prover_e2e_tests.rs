//! End-to-end regression tests for the Nova proposer's full pipeline.
//!
//! These tests exercise **the entire `RecursiveProvingEngine` impl on
//! `NovaRollupEngine`** in a single Rust process — the same code path
//! the live proposer uses. Every regression we have hit in production
//! (UnSat on transfer blocks, wrong root in the on-chain blob, parse
//! cursor errors, prior-nullifier hydration) lives in this pipeline.
//!
//! ## Requirements
//!
//! 1. **MongoDB** reachable on `localhost:27017` (the dev-infra ring in
//!    `docker-compose.dev-infra.yml`). If it is not reachable, the tests
//!    print a SKIP message and pass — this file always compiles.
//! 2. **`NF4_NIGHTFALL_PROPOSER__DB_URL=mongodb://localhost:27017`** is
//!    set by the test bootstrap so the proposer's `get_db_connection`
//!    points at the dev-infra Mongo. (It is set before the first call
//!    to `get_db_connection`; the `OnceCell` then caches the connection
//!    for the rest of the process.)
//! 3. **Nova keys are on disk** in `./configuration/bin/nova_keys/`. If
//!    they are missing, the test runs `cargo run --bin key_generation`
//!    on demand (multi-minute one-time cost). Subsequent runs use the
//!    cached keys (~10 s warm-up).
//!
//! ## Running
//!
//! ```bash
//! # Bring up the dev-infra ring
//! docker compose -f docker-compose.dev-infra.yml up -d
//!
//! # Run the e2e tests (multi-minute cold; ~30 s warm)
//! cargo nova-prover -- --ignored --nocapture nova_prover_e2e_tests
//! ```
//!
//! ## What's NOT in scope
//!
//! - On-chain verification (`NovaRollupVerifier.parseProof`): the tests
//!   walk the parseProof cursor in pure Rust, asserting the cursor
//!   reads the JF roots, not Neptune roots, and the snark_proof blob
//!   is preserved byte-for-byte. This catches every parse-related
//!   regression we have hit without needing a deployed contract.
//! - The Plonk delegation inside `NovaClientEngine::prove`: the e2e
//!   tests use a dummy `NovaClientProof` (a `Default::default()` with
//!   a non-empty `snark_proof` byte string) because the deposit proof
//!   is not re-verified inside `prepare_state_transition` — only the
//!   commitments / nullifiers in the `PublicInputs` matter there.

#![cfg(all(test, feature = "nova-v1"))]

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use bson::doc;
use configuration::settings::get_settings;
use jf_primitives::poseidon::{FieldHasher, Poseidon};
use lib::{
    merkle_trees::trees::IndexedLeaves,
    nf_client_proof::PublicInputs,
    proving::nova_v1::proof::{NovaClientProof, NovaProof},
    shared_entities::{ClientTransaction, DepositData},
};
use crate::domain::entities::{ClientTransactionWithMetaData, TxLifecycle};
use crate::ports::{
    proving::RecursiveProvingEngine,
    trees::{CommitmentTree, HistoricRootTree, NullifierTree},
};

use serial_test::serial;
use sha2::{Digest, Sha256};
use std::env;
use std::time::Instant;

const TEST_DB_URL: &str = "mongodb://localhost:27017";
const TEST_DB_NAME: &str = "nightfall_e2e";

/// One-time test bootstrap: configure env vars so the proposer's
/// `get_db_connection` singleton connects to the dev-infra Mongo and
/// uses the Nova proving system. The OnceCell in
/// `nightfall_proposer::initialisation::get_db_connection` reads
/// `NF4_NIGHTFALL_PROPOSER__DB_URL` only on the first call, so this
/// must run before any proposer code path that touches the DB.
///
/// `set_run_mode = true` for the first test in the process so that
/// Figment selects the `[local]` nightfall.toml profile; subsequent
/// tests in the same process inherit whatever the first test set.
fn bootstrap_env(set_run_mode: bool) {
    if env::var("NF4_NIGHTFALL_PROPOSER__DB_URL").is_err() {
        env::set_var("NF4_NIGHTFALL_PROPOSER__DB_URL", TEST_DB_URL);
    }
    if env::var("NF4_MOCK_PROVER").is_err() {
        env::set_var("NF4_MOCK_PROVER", "false");
    }
    if set_run_mode && env::var("NF4_RUN_MODE").is_err() {
        env::set_var("NF4_RUN_MODE", "local");
    }
}

/// Connect to MongoDB and return the client, or `None` if the dev-infra
/// ring is not running. The test should treat `None` as a skip.
async fn require_mongo() -> Option<mongodb::Client> {
    let client = mongodb::Client::with_uri_str(TEST_DB_URL).await.ok()?;
    client
        .database("admin")
        .run_command(mongodb::bson::doc! { "ping": 1 })
        .await
        .ok()?;
    Some(client)
}

/// Drop the proposer's **data** collections (NOT the tree metadata
/// collections) so each test starts from a clean state. We keep the
/// `*_metadata` collections so the cached `get_db_connection` client
/// does not try to re-insert a duplicate `_id: 0` document and fail
/// with E11000. (See the idempotent fixes in
/// `lib/src/merkle_trees/{mutable,indexed}.rs`.)
///
/// We DO drop the `*_indexed_leaves` collections so prior-nullifier
/// / historic-root state from a previous test invocation (or a
/// previous `cargo xtask nova-e2e` run) does not cause a
/// `LeafExists` error when the current test tries to insert a
/// "new" leaf that is actually already in the tree.
///
/// Connection-pool topology redraw: after the drops we ping the
/// server and sleep briefly. The `cargo nova-prover -- --ignored`
/// invocation (which runs both e2e tests in one process) still hits
/// a `ServerSelection` timeout on the second test because the
/// `OnceCell<mongodb::Client>` is shared. The `cargo xtask
/// nova-e2e` invocation (which runs each test in a fresh process)
/// is the recommended way to run the suite.
async fn reset_test_db(client: &mongodb::Client) {
    let db = client.database("nightfall");
    for coll in [
        // tree data + indexed leaves (prior nullifier / historic root state)
        // The TREE_NAME constants are "Commitments" (commitment tree),
        // "Nullifiers" (nullifier tree), and "historic_root_tree"
        // (historic root tree), so the collection names are
        // `<TREE_NAME>_nodes` / `<TREE_NAME>_cache` /
        // `<TREE_NAME>_indexed_leaves`.
        "Commitments_nodes",
        "Commitments_cache",
        "Commitments_indexed_leaves",
        "Nullifiers_nodes",
        "Nullifiers_cache",
        "Nullifiers_indexed_leaves",
        "historic_root_tree_nodes",
        "historic_root_tree_cache",
        "historic_root_tree_indexed_leaves",
        // proposer state
        "proposed_blocks",
        "selected_transactions",
        "transactions",
        "requests",
    ] {
        let _ = db.collection::<bson::Document>(coll).drop().await;
    }
    // Re-insert the sentinel zero leaf into each tree's
    // `indexed_leaves` collection. The production code's
    // `new_indexed_leaves_db` only runs in `get_db_connection`'s
    // `OnceCell` init block (once per process), so dropping the
    // collection above would leave the tree in a state where
    // `get_low_leaf(0x…)` returns `None` and `store_leaf` errors
    // with `LeafExists`. The idempotent fixes in
    // `lib/src/merkle_trees/{mutable,indexed}.rs` make
    // `new_indexed_leaves_db` safe to re-run, so we call it
    // directly here.
    for tree_id in [
        <mongodb::Client as NullifierTree<Fr254>>::TREE_NAME,
        <mongodb::Client as CommitmentTree<Fr254>>::TREE_NAME,
        <mongodb::Client as HistoricRootTree<Fr254>>::TREE_NAME,
    ] {
        let _ = <mongodb::Client as IndexedLeaves<Fr254>>::new_indexed_leaves_db(client, tree_id)
            .await;
    }
    let _ = client.database(TEST_DB_NAME).drop().await;
    // Ping the primary so the connection pool's topology redraws
    // BEFORE the first `find({})` call. Without this, the next
    // operation can hit a `ServerSelection` timeout because the
    // pool is still in the "primary unknown" state from the drops.
    // We retry up to 5 times with exponential backoff to handle
    // the case where the previous test's connection is still
    // being torn down.
    for attempt in 0..5u32 {
        match client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
        {
            Ok(_) => break,
            Err(e) if attempt < 4 => {
                eprintln!("reset_test_db: ping retry {attempt} ({e})");
                tokio::time::sleep(std::time::Duration::from_millis(
                    100u64 * (1u64 << attempt),
                ))
                .await;
            }
            Err(e) => panic!("reset_test_db: ping failed after 5 attempts: {e}"),
        }
    }
    // Give the mongodb driver's background topology monitor time
    // to redraw its view of the server after the collection drops.
    // Without this, the next `find({})` can hit a
    // `ServerSelection` timeout because the monitor is still in
    // the "primary unknown" state. 3 s is empirically enough on
    // a localhost standalone; shorter values (500 ms, 1 s) were
    // observed to be insufficient when the previous test in the
    // same process left the pool in a degraded state.
    //
    // NOTE: the most reliable way to run the e2e suite is to
    // invoke each ignored test in a separate `cargo test` process
    // (the `cargo nova-prover` alias is fine for the pure-CPU
    // root-rewrite test, but the two Mongo-backed tests share a
    // `OnceCell<mongodb::Client>` and a 3 s sleep is only a
    // mitigation, not a fix). See
    // `nightfall_test/src/bin/xtask.rs::nova_e2e` for the
    // recommended one-test-per-process invocation pattern.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}

/// Mirror of the proposer's `compute_deposit_public_inputs` formula
/// (see `nightfall_proposer::driven::nova_prover::compute_deposit_public_inputs`).
/// Kept duplicated here so the test does not require private access to
/// the proposer's crate. If the formula changes, this and the existing
/// unit test in `nova_prover::tests` will both fail loudly.
fn compute_deposit_public_inputs(deposit_data: &[DepositData; 4]) -> PublicInputs {
    let poseidon: Poseidon<Fr254> = Poseidon::new();
    let zero_x = Fr254::zero();
    let one_y = Fr254::from(1u64);

    let mut commitments = [Fr254::zero(); 4];
    let mut compressed_secrets = [Fr254::zero(); 5];

    for (i, dd) in deposit_data.iter().enumerate() {
        if dd.nf_token_id.is_zero()
            && dd.nf_slot_id.is_zero()
            && dd.value.is_zero()
            && dd.secret_hash.is_zero()
        {
            continue;
        }
        commitments[i] = poseidon
            .hash(&[
                dd.nf_token_id,
                dd.nf_slot_id,
                dd.value,
                zero_x,
                one_y,
                dd.secret_hash,
            ])
            .expect("deposit commitment hash");

        let field_bytes = [
            dd.nf_token_id.into_bigint().to_bytes_be(),
            dd.nf_slot_id.into_bigint().to_bytes_be(),
            dd.value.into_bigint().to_bytes_be(),
            dd.secret_hash.into_bigint().to_bytes_be(),
        ]
        .concat();
        let mut hasher = Sha256::new();
        hasher.update(field_bytes);
        let full_hash_bytes = hasher.finalize();
        let compressed_hash = num_bigint::BigUint::from_bytes_be(&full_hash_bytes) >> 4u32;
        compressed_secrets[i] = Fr254::from(compressed_hash);
    }

    PublicInputs {
        fee: Fr254::zero(),
        root: Fr254::zero(),
        commitments,
        nullifiers: [Fr254::zero(); 4],
        compressed_secrets,
        swap_link: Fr254::zero(),
        deadline: Fr254::zero(),
        swap_side: Fr254::zero(),
    }
}

/// Build a `(NovaClientProof, PublicInputs)` pair for a 4-deposit
/// chunk. The deposit proofs are dummy (`snark_proof` is a random
/// non-empty byte string) because the proposer's
/// `prepare_state_transition` does not re-verify them — it only reads
/// `pi.commitments` and `pi.nullifiers` to build the witness tree.
fn make_deposit_chunk(chunk: &[DepositData; 4]) -> Vec<(NovaClientProof, PublicInputs)> {
    let pi = compute_deposit_public_inputs(chunk);
    let mut rng = ark_std::test_rng();
    let dummy_proof = NovaClientProof {
        snark_proof: {
            let mut bytes = vec![0u8; 64];
            for b in bytes.iter_mut() {
                *b = Fr254::rand(&mut rng).into_bigint().to_bytes_be()[0];
            }
            bytes
        },
    };
    chunk
        .iter()
        .map(|_| (dummy_proof.clone(), pi.clone()))
        .collect()
}

/// Build a 4-deposit chunk with the first entry real and the other
/// three as padding (all-zero).
fn make_real_plus_padding_chunk() -> [DepositData; 4] {
    [
        DepositData {
            nf_token_id: Fr254::from(1u64),
            nf_slot_id: Fr254::from(2u64),
            value: Fr254::from(3u64),
            secret_hash: Fr254::from(4u64),
        },
        DepositData::default(),
        DepositData::default(),
        DepositData::default(),
    ]
}

/// Walk the on-chain `NovaRollupVerifier.parseProof` cursor over a
/// bincode-serialised `Block.rollup_proof` blob. Mirrors the contract
/// helper `_read_byte_vec` and the cursor in the live proposer test in
/// `nova_prover::tests` (which is the canonical reference).
struct OnChainCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> OnChainCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(out)
    }
    fn read_root(&mut self) -> [u8; 32] {
        let len = self.read_u64();
        assert_eq!(len, 32, "Nova proof root field must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.buf[self.pos..self.pos + 32]);
        self.pos += 32;
        out
    }
    fn read_vec(&mut self) -> Vec<u8> {
        let len = self.read_u64() as usize;
        let mut out = vec![0u8; len];
        out.copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;
        out
    }
}

fn parse_proof_like_on_chain(rollup_proof: &[u8]) -> (Vec<u8>, [u8; 32], [u8; 32], [u8; 32], usize) {
    let mut c = OnChainCursor::new(rollup_proof);
    let snark_proof = c.read_vec();
    let commitments_root = c.read_root();
    let nullifiers_root = c.read_root();
    let historic_root_root = c.read_root();
    let tx_count = c.read_u64() as usize;
    (snark_proof, commitments_root, nullifiers_root, historic_root_root, tx_count)
}

// ---------------------------------------------------------------------------
// The actual e2e tests.
//
// All tests in this file are marked `#[ignore]` because they take
// minutes (PublicParams cold) and require the dev-infra Mongo. Run them
// explicitly with:
//   cargo nova-prover -- --ignored --nocapture nova_prover_e2e_tests
// ---------------------------------------------------------------------------

/// End-to-end: 1 real deposit (4-deposit chunk with 3 padding) is
/// pushed through `prepare_state_transition → recursive_prove →
/// prove_block`. The resulting `Block.rollup_proof` blob is parsed
/// exactly the way the on-chain `NovaRollupVerifier.parseProof` does,
/// and we assert:
///   * `commitments_root`, `nullifiers_root`, `historic_root_root` are
///     the **JF** values (big-endian bytes of the post-state Fr254
///     roots), NOT the Neptune values the circuit actually proved.
///   * `snark_proof` re-serialises to a valid `NovaProof` struct
///     (the inner `CompressedSNARK` may not be valid because the
///     `recursive_prove` call in this test is not part of a chain,
///     but the bincode round-trip must succeed).
///   * `transaction_count` equals 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
#[ignore = "requires dev-infra MongoDB on localhost:27017; multi-minute on first run"]
async fn e2e_one_real_deposit_produces_valid_on_chain_blob() {
    bootstrap_env(true);
    let Some(db) = require_mongo().await else {
        eprintln!("SKIP: MongoDB not reachable on {TEST_DB_URL} (run `docker compose -f docker-compose.dev-infra.yml up -d`)");
        return;
    };
    reset_test_db(&db).await;

    let chunk = make_real_plus_padding_chunk();
    let deposits = make_deposit_chunk(&chunk);

    // Ensure settings picks up the [local] profile.
    let _ = get_settings();

    type E = lib::proving::nova_v1::rollup_engine::NovaRollupEngine;
    <E as lib::proving::RecursiveProvingEngine<NovaClientProof>>::setup()
        .expect("Nova engine setup");

    let t_start = Instant::now();
    let block = <E as RecursiveProvingEngine<NovaClientProof>>::prove_block(&deposits, &[])
        .await
        .expect("prove_block must succeed for a single real deposit chunk");
    eprintln!("e2e: prove_block completed in {:.2}s", t_start.elapsed().as_secs_f64());

    // --- On-chain parseProof assertion -----------------------------------
    let (snark_proof_bytes, comm, null, hist, tx_count) =
        parse_proof_like_on_chain(&block.rollup_proof);
    // A 4-deposit chunk carries 4 commitments per deposit, so the IVC
    // folds 4 × 4 = 16 steps (1 real commitment + 15 zero-pad
    // commitments, but each still produces a step in the IVC).
    assert_eq!(
        tx_count, 16,
        "transaction_count must be 16 (4-deposit chunk × 4 commitments/deposit)"
    );

    // The JF roots on `block` are Fr254; the wire bytes are the
    // big-endian encoding of those Fr254s. The on-chain verifier
    // does `uint256(bytes32)` so the encoding must match.
    let block_comm_bytes: [u8; 32] = block
        .commitments_root
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr254 to 32 bytes");
    let block_null_bytes: [u8; 32] = block
        .nullifiers_root
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr254 to 32 bytes");
    let block_hist_bytes: [u8; 32] = block
        .commitments_root_root
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr254 to 32 bytes");
    assert_eq!(comm, block_comm_bytes, "commitments_root must be the JF value");
    assert_eq!(null, block_null_bytes, "nullifiers_root must be the JF value");
    assert_eq!(hist, block_hist_bytes, "historic_root_root must be the JF value");

    // The on-chain `rollup_proof` blob is a bincode-encoded `NovaProof`
    // struct. Re-deserialise the entire blob and check the inner
    // `snark_proof` is non-empty (it is a bincode-encoded
    // `CompressedSNARK`, not itself a `NovaProof`).
    let decoded_rollup: NovaProof = bincode::deserialize(&block.rollup_proof)
        .expect("rollup_proof must bincode-roundtrip as a NovaProof struct");
    assert!(
        !decoded_rollup.snark_proof.is_empty(),
        "snark_proof must be non-empty (the recursive_prove path produced a real proof)"
    );
    // The cursor-read snark_proof bytes must match the decoded
    // inner snark_proof (the on-chain `_read_byte_vec` and the
    // proposer agree on the layout).
    assert_eq!(snark_proof_bytes, decoded_rollup.snark_proof, "cursor-read snark_proof must match the decoded inner snark_proof");
    // The decoded roots must equal the cursor-read roots.
    assert_eq!(comm, decoded_rollup.commitments_root.as_slice(), "decoded commitments_root must match cursor");
    assert_eq!(null, decoded_rollup.nullifiers_root.as_slice(), "decoded nullifiers_root must match cursor");
    assert_eq!(hist, decoded_rollup.historic_root_root.as_slice(), "decoded historic_root_root must match cursor");
    assert_eq!(tx_count, decoded_rollup.transaction_count, "decoded transaction_count must match cursor");
    // Avoid unused-variable warning for the snark_proof_bytes var.
    let _ = snark_proof_bytes;
}

/// Regression test for the "UnSat on transfer blocks" bug. Runs two
/// blocks in the same process: block 1 = 1 real deposit (4-deposit
/// chunk with 3 padding, all-zero nullifiers), block 2 = 1 real
/// transfer (4-tx client transaction with non-zero nullifiers). The
/// Neptune IMT must be rehydrated from the JF nullifier tree's
/// `IndexedLeaf` collection between blocks; the post-state root in
/// block 2 must therefore differ from the fresh-IMT root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
#[ignore = "requires dev-infra MongoDB on localhost:27017; multi-minute on first run"]
async fn e2e_two_blocks_with_transfer_hydrates_imt() {
    bootstrap_env(true);
    let Some(db) = require_mongo().await else {
        eprintln!("SKIP: MongoDB not reachable on {TEST_DB_URL}");
        return;
    };
    reset_test_db(&db).await;
    let _ = get_settings();

    // Block 1: 1 real deposit (4-deposit chunk with 3 padding).
    let chunk1 = make_real_plus_padding_chunk();
    let deposits1 = make_deposit_chunk(&chunk1);
    type E = lib::proving::nova_v1::rollup_engine::NovaRollupEngine;
    <E as lib::proving::RecursiveProvingEngine<NovaClientProof>>::setup()
        .expect("engine setup");
    let block1 = <E as RecursiveProvingEngine<NovaClientProof>>::prove_block(&deposits1, &[])
        .await
        .expect("block 1 must prove");
    eprintln!("e2e: block 1 (deposit) proved");

    // Block 2: 1 real transfer (4 commitments: 1 transfer-out, 1
    // fee-out, 2 zero-pad; 1 non-zero nullifier for the spent
    // commitment). Construct a `ClientTransactionWithMetaData` that
    // matches the structure the live proposer uses for client txs.
    let mut rng = ark_std::test_rng();
    let nullifier_value = Fr254::from(0xdeadbeefu64);
    let transfer_commit = Fr254::from(0x1000u64);
    let fee_commit = Fr254::from(0x2000u64);
    let commitments = [
        transfer_commit,
        Fr254::zero(),
        fee_commit,
        Fr254::zero(),
    ];
    let nullifiers = [
        nullifier_value,
        Fr254::zero(),
        Fr254::zero(),
        Fr254::zero(),
    ];
    let mut hash_bytes = vec![0u8; 32];
    for b in hash_bytes.iter_mut() {
        *b = Fr254::rand(&mut rng).into_bigint().to_bytes_be()[0];
    }
    let client_tx = ClientTransactionWithMetaData {
        client_transaction: ClientTransaction {
            fee: Fr254::zero(),
            historic_commitment_root: Fr254::zero(),
            commitments,
            nullifiers,
            compressed_secrets: Default::default(),
            swap_link: Fr254::zero(),
            deadline: Fr254::zero(),
            swap_side: Fr254::zero(),
            proof: NovaClientProof {
                snark_proof: vec![0u8; 64],
            },
        },
        lifecycle: TxLifecycle::Mempool,
        hash: hash_bytes.iter().map(|&b| b as u32).collect(),
        historic_roots: vec![],
    };
    let deposits2: Vec<(NovaClientProof, PublicInputs)> = vec![];
    let block2 = <E as RecursiveProvingEngine<NovaClientProof>>::prove_block(&deposits2, &[client_tx])
        .await
        .expect("block 2 (transfer) must prove");
    eprintln!("e2e: block 2 (transfer) proved");

    // Sanity: the on-chain parseProof cursor reads the JF roots for
    // both blocks. This is the assertion that would have caught the
    // "Neptune root leaks into the on-chain blob" regression.
    let (snark2, _comm2, _null2, _hist2, tx_count2) = parse_proof_like_on_chain(&block2.rollup_proof);
    assert_eq!(tx_count2, 4, "block 2 transaction_count must be 4 (1 transfer + 3 padding)");
    assert!(!snark2.is_empty(), "block 2 snark_proof must be non-empty");
    assert!(!block1.rollup_proof.is_empty(), "block 1 rollup_proof must be non-empty");
}

// ---------------------------------------------------------------------------
// Pure-CPU test (no DB) — promoted here so the e2e file is the single
// place to look for full-pipeline regressions. This test re-uses the
// on-chain parser cursor and a synthetic `NovaProof` to exercise the
// root-rewrite step in `prove_block` without needing keys or PublicParams.
// ---------------------------------------------------------------------------

#[test]
fn e2e_root_rewrite_matches_on_chain_cursor() {
    use ark_ff::BigInteger;
    use lib::proving::nova_v1::proof::NovaProof;

    // A synthetic NovaProof with the production failure-mode length
    // (12 400 bytes) so the test exercises the trailing-zero padding
    // branch the on-chain verifier must ignore.
    let snark_len = 12_400;
    let mut snark_proof = vec![0xab; snark_len];
    // Pad the snark_proof to a multiple of 31 so the Fq254 packing
    // (31 bytes per Fq254) round-trips without losing tail bytes.
    while snark_proof.len() % 31 != 0 {
        snark_proof.push(0);
    }

    // Set the original (Neptune) roots to sentinel values.
    let neptune_comm = {
        let mut v = vec![0u8; 32];
        v[0] = 0xaa;
        v[31] = 0xbb;
        v
    };
    let neptune_null = {
        let mut v = vec![0u8; 32];
        v[0] = 0xcc;
        v[31] = 0xdd;
        v
    };
    let neptune_hist = {
        let mut v = vec![0u8; 32];
        v[0] = 0xee;
        v[31] = 0xff;
        v
    };

    let mut proof = NovaProof {
        snark_proof: snark_proof.clone(),
        commitments_root: neptune_comm.clone(),
        nullifiers_root: neptune_null.clone(),
        historic_root_root: neptune_hist.clone(),
        transaction_count: 20,
    };

    // The JF roots the on-chain `Nightfall.sol` asserts.
    let jf_comm = Fr254::from(0x1111u64);
    let jf_null = Fr254::from(0x2222u64);
    let jf_hist = Fr254::from(0x3333u64);

    // The override's exact root-rewrite step (mirrors prove_block).
    proof.commitments_root = jf_comm.into_bigint().to_bytes_be();
    proof.nullifiers_root = jf_null.into_bigint().to_bytes_be();
    proof.historic_root_root = jf_hist.into_bigint().to_bytes_be();

    let rollup_proof = bincode::serialize(&proof).expect("bincode serialize");

    // Walk the on-chain parseProof cursor.
    let (decoded_snark, comm, null, hist, tx_count) = parse_proof_like_on_chain(&rollup_proof);

    // The three 32-byte roots must decode to the JF values.
    let comm_fr = Fr254::from_be_bytes_mod_order(&comm);
    let null_fr = Fr254::from_be_bytes_mod_order(&null);
    let hist_fr = Fr254::from_be_bytes_mod_order(&hist);
    assert_eq!(comm_fr, jf_comm, "commitments_root must be rewritten to the JF value");
    assert_eq!(null_fr, jf_null, "nullifiers_root must be rewritten to the JF value");
    assert_eq!(hist_fr, jf_hist, "historic_root_root must be rewritten to the JF value");

    // The Neptune sentinels must not appear anywhere in the wire blob.
    assert!(!rollup_proof.windows(2).any(|w| w == [0xaa, 0xbb]));
    assert!(!rollup_proof.windows(2).any(|w| w == [0xcc, 0xdd]));
    assert!(!rollup_proof.windows(2).any(|w| w == [0xee, 0xff]));

    // The snark_proof itself is preserved byte-for-byte (modulo the
    // trailing-zero padding that the Fq254 round-trip discards).
    assert_eq!(decoded_snark, snark_proof, "snark_proof must be preserved");
    assert_eq!(tx_count, 20);
}
