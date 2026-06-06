//! Snapshot / restore of the proposer's authoritative JF Merkle trees.
//!
//! The proposer mutates the commitment / nullifier / historic-root trees
//! **speculatively at prove time** (see the `prepare_state_transition`
//! implementations). A block can subsequently fail to land on-chain (rejected
//! `propose_block`, lost turn, or superseded by another proposer's block at the
//! same height), leaving the local trees ahead of the confirmed chain tip with
//! no way to recover short of the heavyweight `reset_tree` + full event replay.
//!
//! This module provides a per-block **snapshot** taken immediately before a
//! block's speculative inserts, and a **restore** used to roll the trees back
//! to that captured state when the block fails. Snapshots are full copies of
//! the trees' MongoDB collections, taken server-side with `$out` (so no tree
//! data is round-tripped through the proposer process). Because a rollback must
//! keep the JF root **byte-identical** to what the chain recomputes, a verbatim
//! copy is used rather than a surgical truncation (which would have to re-derive
//! frontier hashes and risk a root mismatch). Surgical truncation is a possible
//! future optimisation for the per-block snapshot cost.
//!
//! The lifecycle (which snapshot to keep, drop, or restore) is owned by
//! `speculative_state`; this module only performs the raw collection I/O.

use mongodb::bson::{doc, Document};
use mongodb::Client;

const DB_NAME: &str = "nightfall";

/// The MongoDB collections that make up the three authoritative JF trees.
/// `Commitments` / `Nullifiers` / `historic_root_tree` mirror the `TREE_NAME`
/// constants in `driven::db::{commitment_tree, nullifier_tree, historic_root_tree}`.
/// Each mutable tree stores `_metadata`, `_nodes` and `_cache`; the nullifier
/// tree additionally stores `_indexed_leaves` (the indexed-Merkle low-leaf
/// linked list).
fn tree_collections() -> Vec<String> {
    let mut names = Vec::new();
    for tree in ["Commitments", "Nullifiers", "historic_root_tree"] {
        names.push(format!("{tree}_metadata"));
        names.push(format!("{tree}_nodes"));
        names.push(format!("{tree}_cache"));
    }
    names.push("Nullifiers_indexed_leaves".to_string());
    names
}

fn backup_name(collection: &str, suffix: &str) -> String {
    format!("{collection}__snap_{suffix}")
}

/// Run a single-stage `$out` aggregation copying `source` → `dest` (same DB).
/// `$out` replaces `dest` wholesale with the documents read from `source`.
async fn copy_collection(client: &Client, source: &str, dest: &str) -> Result<(), String> {
    let db = client.database(DB_NAME);
    let mut cursor = db
        .collection::<Document>(source)
        .aggregate(vec![doc! {"$out": dest}])
        .await
        .map_err(|e| format!("aggregate $out {source}->{dest} failed: {e}"))?;
    // `$out` executes server-side; drive the (empty) cursor to completion so
    // the write is guaranteed to have happened before we return.
    while cursor
        .advance()
        .await
        .map_err(|e| format!("draining $out cursor {source}->{dest} failed: {e}"))?
    {}
    Ok(())
}

async fn count(client: &Client, collection: &str) -> Result<u64, String> {
    client
        .database(DB_NAME)
        .collection::<Document>(collection)
        .count_documents(doc! {})
        .await
        .map_err(|e| format!("count {collection} failed: {e}"))
}

async fn drop_collection(client: &Client, collection: &str) -> Result<(), String> {
    client
        .database(DB_NAME)
        .collection::<Document>(collection)
        .drop()
        .await
        .map_err(|e| format!("drop {collection} failed: {e}"))
}

/// Capture the current state of the three trees into backup collections tagged
/// with `suffix`. Empty source collections are intentionally not copied (a
/// `$out` of zero documents is unreliable across server versions); their
/// emptiness is reproduced at restore time by dropping the live collection.
pub async fn snapshot(client: &Client, suffix: &str) -> Result<(), String> {
    for collection in tree_collections() {
        let backup = backup_name(&collection, suffix);
        // Start from a clean backup so a stale one can never be restored.
        drop_collection(client, &backup).await?;
        if count(client, &collection).await? > 0 {
            copy_collection(client, &collection, &backup).await?;
        }
    }
    Ok(())
}

/// Restore the three trees from the backup tagged with `suffix`, returning them
/// to exactly the state captured by `snapshot`. A live collection whose backup
/// is absent (it was empty when snapshotted) is dropped.
pub async fn restore(client: &Client, suffix: &str) -> Result<(), String> {
    for collection in tree_collections() {
        let backup = backup_name(&collection, suffix);
        if count(client, &backup).await? > 0 {
            copy_collection(client, &backup, &collection).await?;
        } else {
            drop_collection(client, &collection).await?;
        }
    }
    Ok(())
}

/// Drop the backup collections tagged with `suffix` (the snapshot is no longer
/// needed, e.g. the block it guarded has been confirmed).
pub async fn drop_snapshot(client: &Client, suffix: &str) -> Result<(), String> {
    for collection in tree_collections() {
        drop_collection(client, &backup_name(&collection, suffix)).await?;
    }
    Ok(())
}
