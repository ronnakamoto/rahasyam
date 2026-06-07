//! Lifecycle manager for the proposer's speculative tree state.
//!
//! The proposer advances its authoritative JF trees at prove time, before the
//! block's `BlockProposed` event is confirmed (see the `prepare_state_transition`
//! implementations). Each such speculative block is tracked here together with a
//! snapshot of the trees taken **immediately before** its inserts, so the trees
//! can be rolled back to the confirmed tip if the block fails to land.
//!
//! ## Invariants
//! - The queue holds one entry per outstanding (proven-but-unconfirmed)
//!   speculative block, **in block order** (front = next height to confirm).
//!   Block assembly is sequential, and the event handler processes blocks
//!   strictly in order, so this ordering is preserved.
//! - Each entry's `snapshot_suffix` identifies a full backup of the three trees
//!   in the state that existed *before* that block's inserts — i.e. the tip
//!   after the previous block. Restoring the **front** entry's snapshot reverts
//!   every outstanding speculative block back to the confirmed tip.
//! - `root` is the block's `commitments_root`, set once the block has been
//!   successfully prepared. It is `None` only for an in-progress prepare.
//!
//! ## Usage
//! - `begin` — before a block's speculative inserts (snapshot the pre-state).
//! - `confirm_prepare` — after a successful prepare (record the block's root).
//! - `abort_prepare` — if prepare fails (restore + discard the pre-state).
//! - `confirm_front` — when our own block's event is observed (drop its
//!   snapshot; the block is now confirmed).
//! - `rollback_all` — when a speculative block fails / is superseded (restore to
//!   the confirmed tip and discard all outstanding speculation).
//! - `discard_all` — when the trees are reset (`restart_event_listener`); the
//!   trees are wiped independently, so only the backups need dropping.

use crate::driven::tree_snapshot;
use ark_bn254::Fr as Fr254;
use log::{error, warn};
use mongodb::Client;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, MutexGuard, OnceCell};

/// Serialises all mutations of the authoritative JF trees that can run on
/// different tasks: the assembly task's speculative `prepare` inserts, the event
/// listener's append/rollback, and the finality task's rollback-on-failure.
/// Without it a rollback's collection-level restore could interleave with an
/// in-flight `prepare`'s per-node writes and corrupt a tree.
///
/// This is a **leaf** lock — code holding it only touches the trees and the
/// `queue` below, never `sync_status` or `pending_blocks` — so the global lock
/// order `{sync_status, pending_blocks} > tree_mutation > queue` has no cycle.
pub async fn tree_mutation_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();
    LOCK.get_or_init(|| async { Mutex::new(()) })
        .await
        .lock()
        .await
}

#[derive(Debug, Clone)]
struct SpeculativeBlock {
    /// `commitments_root` of the block, or `None` while its prepare is in flight.
    root: Option<Fr254>,
    /// Identifies the backup of the trees' pre-insert state for this block, or
    /// `None` if the snapshot could not be taken (in which case this block can
    /// still be skip-appended via `confirm_front`, but cannot be rolled back —
    /// any resulting divergence falls through to the reset + replay net).
    snapshot_suffix: Option<String>,
}

// ---------------------------------------------------------------------------
// Pure queue operations (no I/O) — unit-tested below. The async functions are
// thin wrappers that pair these with the tree snapshot/restore side effects.
// ---------------------------------------------------------------------------

/// Track a new in-progress speculative block (root filled in later).
fn q_push(queue: &mut VecDeque<SpeculativeBlock>, snapshot_suffix: Option<String>) {
    queue.push_back(SpeculativeBlock {
        root: None,
        snapshot_suffix,
    });
}

/// Set the root of the most recently pushed (still in-progress) block.
fn q_set_back_root(queue: &mut VecDeque<SpeculativeBlock>, root: Fr254) {
    if let Some(block) = queue.back_mut() {
        if block.root.is_none() {
            block.root = Some(root);
        }
    }
}

/// Pop the back entry iff it is still in-progress (prepare failed).
fn q_pop_back_if_unrooted(queue: &mut VecDeque<SpeculativeBlock>) -> Option<SpeculativeBlock> {
    if matches!(queue.back(), Some(b) if b.root.is_none()) {
        queue.pop_back()
    } else {
        None
    }
}

/// Pop the front entry iff its root matches `root` (our own block confirmed).
fn q_pop_front_if_matches(
    queue: &mut VecDeque<SpeculativeBlock>,
    root: Fr254,
) -> Option<SpeculativeBlock> {
    if matches!(queue.front(), Some(b) if b.root == Some(root)) {
        queue.pop_front()
    } else {
        None
    }
}

async fn queue() -> &'static Mutex<VecDeque<SpeculativeBlock>> {
    static QUEUE: OnceCell<Mutex<VecDeque<SpeculativeBlock>>> = OnceCell::const_new();
    QUEUE
        .get_or_init(|| async { Mutex::new(VecDeque::new()) })
        .await
}

fn next_suffix() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    // Process-unique; trees are per-proposer so no cross-process collision.
    format!("{n}")
}

/// Snapshot the trees' current state and start tracking a new speculative block.
/// Must be called **before** the block's tree mutations. The block's root is
/// filled in later by `confirm_prepare`.
///
/// The block is always tracked (so `confirm_front` can later skip the
/// double-append even if the snapshot failed). If the snapshot fails the block
/// is tracked **without** a backup: it cannot be rolled back, and any resulting
/// divergence falls through to the existing reset + replay recovery.
pub async fn begin(client: &Client) {
    let suffix = next_suffix();
    let snapshot_suffix = match tree_snapshot::snapshot(client, &suffix).await {
        Ok(()) => Some(suffix),
        Err(e) => {
            error!("speculative_state::begin failed to snapshot trees (suffix {suffix}): {e}. Speculative rollback for this block will be unavailable.");
            let _ = tree_snapshot::drop_snapshot(client, &suffix).await;
            None
        }
    };
    q_push(&mut *queue().await.lock().await, snapshot_suffix);
}

/// Record the `commitments_root` of the block whose prepare just succeeded.
pub async fn confirm_prepare(commitments_root: Fr254) {
    q_set_back_root(&mut *queue().await.lock().await, commitments_root);
}

/// Roll back the partial mutations of an in-progress block whose prepare failed,
/// restoring the trees to their pre-insert state and discarding the snapshot.
pub async fn abort_prepare(client: &Client) {
    let block = q_pop_back_if_unrooted(&mut *queue().await.lock().await);
    if let Some(suffix) = block.and_then(|b| b.snapshot_suffix) {
        if let Err(e) = tree_snapshot::restore(client, &suffix).await {
            error!(
                "speculative_state::abort_prepare failed to restore trees (suffix {suffix}): {e}"
            );
        }
        let _ = tree_snapshot::drop_snapshot(client, &suffix).await;
    }
}

/// If the front outstanding block matches `commitments_root`, drop its snapshot
/// (it is now confirmed on-chain) and return `true`. This is how the proposer
/// recognises its **own** confirmed block in the event handler and skips
/// re-appending leaves it already inserted at prove time.
pub async fn confirm_front(client: &Client, commitments_root: Fr254) -> bool {
    let block = q_pop_front_if_matches(&mut *queue().await.lock().await, commitments_root);
    match block {
        Some(block) => {
            if let Some(suffix) = block.snapshot_suffix {
                let _ = tree_snapshot::drop_snapshot(client, &suffix).await;
            }
            true
        }
        None => false,
    }
}

/// Roll all outstanding speculative blocks back to the confirmed tip: restore
/// the oldest snapshot (the tip before the first outstanding block) and discard
/// every snapshot. Used when a speculative block fails to land or is superseded.
pub async fn rollback_all(client: &Client) {
    let blocks: Vec<SpeculativeBlock> = {
        let mut q = queue().await.lock().await;
        q.drain(..).collect()
    };
    if blocks.is_empty() {
        return;
    }
    warn!(
        "Rolling back {} speculative block(s) to the confirmed tip",
        blocks.len()
    );
    // The front (oldest) snapshot is the confirmed-tip state; restoring it
    // reverts every speculative block that followed.
    match blocks.first().and_then(|b| b.snapshot_suffix.as_deref()) {
        Some(suffix) => {
            if let Err(e) = tree_snapshot::restore(client, suffix).await {
                error!("speculative_state::rollback_all failed to restore trees (suffix {suffix}): {e}");
            }
        }
        None => {
            error!("speculative_state::rollback_all has no snapshot for the oldest speculative block; trees cannot be reverted here and will rely on reset + replay recovery.");
        }
    }
    for suffix in blocks.iter().filter_map(|b| b.snapshot_suffix.as_deref()) {
        let _ = tree_snapshot::drop_snapshot(client, suffix).await;
    }
}

/// Discard all tracking and backups without restoring (the trees are being
/// reset independently). Used by `restart_event_listener` after `reset_tree`.
pub async fn discard_all(client: &Client) {
    let blocks: Vec<SpeculativeBlock> = {
        let mut q = queue().await.lock().await;
        q.drain(..).collect()
    };
    for suffix in blocks.iter().filter_map(|b| b.snapshot_suffix.as_deref()) {
        let _ = tree_snapshot::drop_snapshot(client, suffix).await;
    }
}

/// Whether any speculative blocks are currently outstanding.
pub async fn has_outstanding() -> bool {
    !queue().await.lock().await.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        q_pop_back_if_unrooted, q_pop_front_if_matches, q_push, q_set_back_root, SpeculativeBlock,
    };
    use ark_bn254::Fr as Fr254;
    use std::collections::VecDeque;

    fn root(n: u64) -> Fr254 {
        Fr254::from(n)
    }

    fn roots(q: &VecDeque<SpeculativeBlock>) -> Vec<Option<Fr254>> {
        q.iter().map(|b| b.root).collect()
    }

    fn snap(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn push_and_confirm_prepare_sets_back_root() {
        let mut q = VecDeque::new();
        q_push(&mut q, snap("0"));
        assert_eq!(roots(&q), vec![None]);
        q_set_back_root(&mut q, root(10));
        assert_eq!(roots(&q), vec![Some(root(10))]);
        // A second confirm must not overwrite an already-rooted entry.
        q_set_back_root(&mut q, root(99));
        assert_eq!(roots(&q), vec![Some(root(10))]);
    }

    #[test]
    fn abort_pops_only_in_progress_back_entry() {
        let mut q = VecDeque::new();
        q_push(&mut q, snap("0"));
        q_set_back_root(&mut q, root(10)); // block 0 prepared
        q_push(&mut q, snap("1")); // block 1 in progress
                                   // Aborting block 1 pops it and returns its snapshot suffix.
        assert_eq!(
            q_pop_back_if_unrooted(&mut q).and_then(|b| b.snapshot_suffix),
            snap("1")
        );
        assert_eq!(roots(&q), vec![Some(root(10))]);
        // With no in-progress entry, abort is a no-op (won't drop a prepared block).
        assert!(q_pop_back_if_unrooted(&mut q).is_none());
        assert_eq!(roots(&q), vec![Some(root(10))]);
    }

    #[test]
    fn confirm_front_matches_in_order() {
        let mut q = VecDeque::new();
        q_push(&mut q, snap("0"));
        q_set_back_root(&mut q, root(10));
        q_push(&mut q, snap("1"));
        q_set_back_root(&mut q, root(11));
        // Our own block 10 confirms: front matches, returns its suffix.
        assert_eq!(
            q_pop_front_if_matches(&mut q, root(10)).and_then(|b| b.snapshot_suffix),
            snap("0")
        );
        // Block 11 is now front.
        assert_eq!(roots(&q), vec![Some(root(11))]);
    }

    #[test]
    fn confirm_front_no_match_leaves_queue_intact() {
        let mut q = VecDeque::new();
        q_push(&mut q, snap("0"));
        q_set_back_root(&mut q, root(10));
        // A different (someone else's) block at this height does not match the
        // front, so nothing is popped — the caller will roll back instead.
        assert!(q_pop_front_if_matches(&mut q, root(999)).is_none());
        assert_eq!(roots(&q), vec![Some(root(10))]);
    }

    #[test]
    fn front_snapshot_is_oldest_for_rollback() {
        // rollback_all restores the FRONT (oldest) snapshot to reach the
        // confirmed tip; confirm the front entry is the earliest pushed.
        let mut q = VecDeque::new();
        q_push(&mut q, snap("tip"));
        q_set_back_root(&mut q, root(10));
        q_push(&mut q, snap("after10"));
        q_set_back_root(&mut q, root(11));
        assert_eq!(q.front().unwrap().snapshot_suffix, snap("tip"));
    }

    #[test]
    fn untracked_snapshot_still_skips_double_append() {
        // A block whose snapshot failed (snapshot_suffix = None) is still
        // tracked so confirm_front skips its double-append.
        let mut q = VecDeque::new();
        q_push(&mut q, None);
        q_set_back_root(&mut q, root(10));
        let popped = q_pop_front_if_matches(&mut q, root(10));
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().snapshot_suffix, None);
    }
}
