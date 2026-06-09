//! Persistent commitment tree for the Nova code path.
//!
//! Each proving system in Nightfall uses its own optimized primitives. The
//! Plonk path keeps using the jf-primitives commitment tree
//! (see `lib::merkle_trees`); the Nova path uses a sparse Merkle tree that
//! hashes with **neptune Poseidon** so the IVC circuit's gadgets can verify
//! the proofs without any bridge layer.
//!
//! The tree is sparse: only nodes that differ from the all-zero default are
//! stored, which is memory-efficient when the tree has few insertions
//! relative to its capacity of `2^depth` leaves.
//!
//! ## Persistence
//!
//! This is the single source of truth for the Nova commitment tree. The
//! shadow-tree pattern (where a second tree was kept in sync with the
//! jf-primitives tree) has been removed: the Nova proposer reads and writes
//! to this tree directly.
//!
//! Persistence is currently in-memory; a future change will add MongoDB
//! collections named `nova_commitment_nodes_{tree_id}` and
//! `nova_commitment_metadata_{tree_id}` mirroring the layout of the
//! existing mutable tree, but using F1 and neptune Poseidon. The trait
//! [`CommitmentTreeStorage`] is the integration point for that.

#![cfg(feature = "nova-v1")]

use std::collections::HashMap;

use ff::{Field, PrimeField};
use generic_array::typenum::U2;
use nova_snark::frontend::gadgets::poseidon::PoseidonConstants;
use serde::{Deserialize, Serialize};

use super::hash::{poseidon_constants, poseidon_hash2_native, poseidon_hash3_native};
use super::merkle::{imt_leaf_hash_native, MerklePathHop};
use super::rollup_engine::F1;
use serde::de::Error as _;
use serde::{Deserializer, Serializer};

/// Encode an F1 (Nova scalar) field element as a `0x`-prefixed 64-char
/// big-endian hex string. We use the `ff::PrimeField::to_repr` API
/// because F1 is not an `arkworks` type and so does not implement
/// `CanonicalSerialize`. This is the canonical wire encoding shared by
/// the proposer (which forwards `z0[1]` to the attestor) and the
/// attestor (which parses it back via [`f1_from_hex`]).
pub fn f1_to_hex(v: &F1) -> String {
    let repr = v.to_repr();
    let bytes = repr.as_ref();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    // big-endian for human-readable display
    let mut hex_str = String::with_capacity(64);
    for byte in padded.iter().rev() {
        use std::fmt::Write;
        write!(&mut hex_str, "{byte:02x}").expect("writing to String never fails");
    }
    format!("0x{hex_str}")
}

/// Parse an F1 (Nova scalar) field element from a `0x`-prefixed or
/// unprefixed big-endian hex string. Inverse of [`f1_to_hex`]. Shorter
/// strings are left-padded with zeros, so any value `f1_to_hex` can emit
/// round-trips.
pub fn f1_from_hex(hex_str: &str) -> Result<F1, String> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() > 64 {
        return Err(format!("F1 hex string too long: {} chars", stripped.len()));
    }
    // Left-pad to a full 64-char (32-byte) big-endian representation.
    let padded_hex = format!("{stripped:0>64}");
    let mut be = [0u8; 32];
    for (i, chunk) in padded_hex.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|e| e.to_string())?, 16)
            .map_err(|e| e.to_string())?;
        be[i] = byte;
    }
    // `from_repr` expects little-endian bytes.
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    let mut repr = <F1 as ff::PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&le);
    let opt = F1::from_repr(repr);
    if opt.is_some().into() {
        Ok(opt.unwrap())
    } else {
        Err("F1::from_repr returned None".to_string())
    }
}

/// Serialize an F1 (Nova scalar) field element as a 0x-prefixed 64-char hex
/// string in big-endian order.
pub fn serialize_f1<S>(v: &F1, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&f1_to_hex(v))
}

/// Deserialize an F1 (Nova scalar) field element from a 0x-prefixed or
/// unprefixed hex string. Inverse of [`serialize_f1`].
pub fn deserialize_f1<'de, D>(d: D) -> Result<F1, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = <&str>::deserialize(d)?;
    f1_from_hex(hex_str).map_err(D::Error::custom)
}

/// One hop in a binary Merkle inclusion path. The Nova circuit consumes
/// this directly; see `super::merkle::verify_merkle_inclusion_circuit`.
pub type CommitmentPath = Vec<MerklePathHop<F1>>;

/// Storage abstraction for the commitment tree.
///
/// The default in-memory implementation is sufficient for proposer
/// unit tests. Production deployments are expected to wire a MongoDB-backed
/// implementation that reads/writes nodes and metadata to a dedicated
/// collection.
pub trait CommitmentTreeStorage: Send + Sync + Clone {
    /// Persist a single node `(level, index) -> hash`.
    fn put_node(&mut self, level: u32, index: u64, hash: F1);
    /// Load a single node, returning `None` if it has never been written
    /// (i.e. the node is the implicit zero).
    fn get_node(&self, level: u32, index: u64) -> Option<F1>;
    /// Read the current `next_leaf_index` and `root`.
    fn load_metadata(&self) -> Option<CommitmentTreeMetadata>;
    /// Flush the current root and `next_leaf_index` to storage.
    fn save_metadata(&mut self, meta: &CommitmentTreeMetadata);
}

/// Persisted metadata for a commitment tree.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CommitmentTreeMetadata {
    pub tree_height: u32,
    pub next_leaf_index: u64,
    #[serde(serialize_with = "serialize_f1", deserialize_with = "deserialize_f1")]
    pub root: F1,
}

/// In-memory `CommitmentTreeStorage` used by tests and the proposer's
/// transient block state. Production deployments override this with a
/// MongoDB-backed storage (see the spec for the proposed schema).
#[derive(Default, Debug, Clone)]
pub struct InMemoryCommitmentStorage {
    nodes: HashMap<(u32, u64), F1>,
    metadata: Option<CommitmentTreeMetadata>,
}

impl InMemoryCommitmentStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CommitmentTreeStorage for InMemoryCommitmentStorage {
    fn put_node(&mut self, level: u32, index: u64, hash: F1) {
        self.nodes.insert((level, index), hash);
    }
    fn get_node(&self, level: u32, index: u64) -> Option<F1> {
        self.nodes.get(&(level, index)).copied()
    }
    fn load_metadata(&self) -> Option<CommitmentTreeMetadata> {
        self.metadata
    }
    fn save_metadata(&mut self, meta: &CommitmentTreeMetadata) {
        self.metadata = Some(*meta);
    }
}

/// Sparse Merkle tree of the commitment set, hashed with neptune Poseidon.
#[derive(Clone)]
pub struct NeptuneCommitmentTree<S: CommitmentTreeStorage> {
    depth: u32,
    /// `next_leaf_index` is the index of the next leaf that will be
    /// inserted. Equal to the number of non-zero leaves.
    next_leaf_index: u64,
    /// Precomputed hash of an all-zero subtree at each level.
    /// `zero_hashes[0] = 0`, `zero_hashes[i] = H(zero_hashes[i-1], zero_hashes[i-1])`.
    zero_hashes: Vec<F1>,
    constants: PoseidonConstants<F1, U2>,
    storage: S,
}

impl<S: CommitmentTreeStorage> NeptuneCommitmentTree<S> {
    /// Create a new empty commitment tree of the given depth.
    pub fn new(depth: u32, mut storage: S) -> Self {
        assert!((depth as u32) < 64, "tree depth must fit in u64 addressing");
        let constants = poseidon_constants::<F1>();
        let mut zero_hashes = vec![F1::ZERO; depth as usize + 1];
        for i in 1..=depth as usize {
            zero_hashes[i] =
                poseidon_hash2_native(&constants, zero_hashes[i - 1], zero_hashes[i - 1]);
        }
        // Eagerly compute the empty-tree root and persist the initial
        // metadata. The root is well-defined for an empty tree (all-zero
        // leaves collapsed up to level `depth`).
        let root = zero_hashes[depth as usize];
        let next_leaf_index = 0u64;
        let meta = CommitmentTreeMetadata {
            tree_height: depth,
            next_leaf_index,
            root,
        };
        storage.save_metadata(&meta);
        Self {
            depth,
            next_leaf_index,
            zero_hashes,
            constants,
            storage,
        }
    }

    /// Hydrate an existing tree from storage. Returns `None` if no
    /// metadata has been written yet.
    pub fn load(storage: S) -> Option<Self> {
        let meta = storage.load_metadata()?;
        let depth = meta.tree_height;
        let constants = poseidon_constants::<F1>();
        let mut zero_hashes = vec![F1::ZERO; depth as usize + 1];
        for i in 1..=depth as usize {
            zero_hashes[i] =
                poseidon_hash2_native(&constants, zero_hashes[i - 1], zero_hashes[i - 1]);
        }
        Some(Self {
            depth,
            next_leaf_index: meta.next_leaf_index,
            zero_hashes,
            constants,
            storage,
        })
    }

    /// Take the storage out of the tree, consuming it. Used by tests to
    /// round-trip through `load`.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Current root.
    pub fn root(&self) -> F1 {
        self.storage
            .get_node(self.depth, 0)
            .unwrap_or(self.zero_hashes[self.depth as usize])
    }

    /// Number of leaves that have been inserted.
    pub fn leaf_count(&self) -> u64 {
        self.next_leaf_index
    }

    /// Tree depth.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    fn get_node(&self, level: u32, index: u64) -> F1 {
        self.storage
            .get_node(level, index)
            .unwrap_or(self.zero_hashes[level as usize])
    }

    /// Append a leaf to the tree. Returns the new root and the sibling
    /// path proving that the leaf is included.
    pub fn append(&mut self, leaf: F1) -> (F1, CommitmentPath) {
        let leaf_index = self.next_leaf_index;
        self.next_leaf_index += 1;
        let path = self.insert_at(leaf_index, leaf);
        let new_root = self.get_node(self.depth, 0);
        let meta = CommitmentTreeMetadata {
            tree_height: self.depth,
            next_leaf_index: self.next_leaf_index,
            root: new_root,
        };
        self.storage.save_metadata(&meta);
        (new_root, path)
    }

    /// Insert a leaf at a specific index, recomputing the path to root.
    /// Exposed for tests; production code uses [`append`](Self::append).
    pub fn insert_at(&mut self, leaf_index: u64, leaf_value: F1) -> CommitmentPath {
        self.storage.put_node(0, leaf_index, leaf_value);
        let mut path = Vec::with_capacity(self.depth as usize);
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = self.get_node(level, sibling_idx);
            let current = self.get_node(level, idx);
            path.push(MerklePathHop { sibling, is_right });

            let parent_idx = idx / 2;
            let (left, right) = if is_right {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let parent_hash = poseidon_hash2_native(&self.constants, left, right);
            self.storage.put_node(level + 1, parent_idx, parent_hash);

            idx = parent_idx;
        }
        path
    }

    /// Build a Merkle inclusion path for an already-inserted leaf.
    pub fn inclusion_path(&self, leaf_index: u64) -> CommitmentPath {
        let mut path = Vec::with_capacity(self.depth as usize);
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = self.get_node(level, sibling_idx);
            path.push(MerklePathHop { sibling, is_right });
            idx /= 2;
        }
        path
    }
}

// ---------------------------------------------------------------------------
// Index Merkle Tree (nullifier) — single source of truth for the Nova path.
// ---------------------------------------------------------------------------

/// One entry of the nullifier IMT's leaf DB. This is the F1-native
/// equivalent of `lib::merkle_trees::trees::IndexedLeaf<Fr254>` and is
/// the data structure that the proposer's witness logic consumes.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct NovaIndexedLeaf {
    #[serde(serialize_with = "serialize_f1", deserialize_with = "deserialize_f1")]
    pub value: F1,
    /// Tree index in the Merkle tree.
    pub index: u64,
    #[serde(serialize_with = "serialize_f1", deserialize_with = "deserialize_f1")]
    pub next_index: F1,
    #[serde(serialize_with = "serialize_f1", deserialize_with = "deserialize_f1")]
    pub next_value: F1,
}

// Re-export the IMT witness type for callers.
pub use super::merkle::ImtNonInclusionWitness;

/// IMT-specific metadata persisted alongside the tree.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct NullifierTreeMetadata {
    pub tree_height: u32,
    /// Counter of the next insertion slot. Persisted so the IMT can be
    /// rehydrated without walking the leaf DB.
    pub next_insert_index: u64,
    #[serde(serialize_with = "serialize_f1", deserialize_with = "deserialize_f1")]
    pub root: F1,
}

/// Storage abstraction for the nullifier IMT. Like the commitment tree,
/// the in-memory implementation is for unit tests; production wires a
/// MongoDB-backed store.
pub trait NullifierTreeStorage: Send + Sync + Clone {
    /// Persist a single Merkle node.
    fn put_node(&mut self, level: u32, index: u64, hash: F1);
    /// Load a single Merkle node.
    fn get_node(&self, level: u32, index: u64) -> Option<F1>;
    /// Persist an indexed leaf (or overwrite an existing one).
    fn put_leaf(&mut self, leaf: &NovaIndexedLeaf);
    /// Load an indexed leaf by its `value` (primary key for non-zero
    /// leaves). Returns `None` for a value that has not been inserted.
    fn get_leaf_by_value(&self, value: F1) -> Option<NovaIndexedLeaf>;
    /// Load an indexed leaf by its tree index.
    fn get_leaf_by_index(&self, index: u64) -> Option<NovaIndexedLeaf>;
    /// Find the low leaf for `value`: the leaf with the largest
    /// `value < needle`. Used when generating a non-inclusion proof.
    fn get_low_leaf(&self, needle: F1) -> Option<NovaIndexedLeaf>;
    /// Persist / load IMT metadata.
    fn load_metadata(&self) -> Option<NullifierTreeMetadata>;
    fn save_metadata(&mut self, meta: &NullifierTreeMetadata);
}

#[derive(Default, Debug, Clone)]
pub struct InMemoryNullifierStorage {
    nodes: HashMap<(u32, u64), F1>,
    leaves_by_value: HashMap<Vec<u8>, NovaIndexedLeaf>,
    leaves_by_index: HashMap<u64, NovaIndexedLeaf>,
    metadata: Option<NullifierTreeMetadata>,
}

impl InMemoryNullifierStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

fn key_of(v: F1) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    let repr = v.to_repr();
    let bytes = repr.as_ref();
    buf.extend_from_slice(bytes);
    buf
}

impl NullifierTreeStorage for InMemoryNullifierStorage {
    fn put_node(&mut self, level: u32, index: u64, hash: F1) {
        self.nodes.insert((level, index), hash);
    }
    fn get_node(&self, level: u32, index: u64) -> Option<F1> {
        self.nodes.get(&(level, index)).copied()
    }
    fn put_leaf(&mut self, leaf: &NovaIndexedLeaf) {
        self.leaves_by_value.insert(key_of(leaf.value), *leaf);
        self.leaves_by_index.insert(leaf.index, *leaf);
    }
    fn get_leaf_by_value(&self, value: F1) -> Option<NovaIndexedLeaf> {
        self.leaves_by_value.get(&key_of(value)).copied()
    }
    fn get_leaf_by_index(&self, index: u64) -> Option<NovaIndexedLeaf> {
        self.leaves_by_index.get(&index).copied()
    }
    fn get_low_leaf(&self, needle: F1) -> Option<NovaIndexedLeaf> {
        self.leaves_by_value
            .values()
            .filter(|l| l.value < needle)
            .max_by_key(|l| l.value)
            .copied()
    }
    fn load_metadata(&self) -> Option<NullifierTreeMetadata> {
        self.metadata
    }
    fn save_metadata(&mut self, meta: &NullifierTreeMetadata) {
        self.metadata = Some(*meta);
    }
}

/// Indexed Merkle tree for the Nova path.
///
/// This is the **single source of truth** for nullifier non-inclusion
/// proofs used by the Nova proposer. The previous shadow-tree pattern
/// (a separate tree kept in sync with the jf-primitives IMT) has been
/// removed. The IMT hashes with neptune Poseidon, which matches the
/// Nova circuit's verification gadgets, eliminating the cross-implementation
/// sync bug class.
#[derive(Clone)]
pub struct NeptuneIMT<S: NullifierTreeStorage> {
    /// Underlying Merkle tree. Level 0 = leaves, level `depth` = root.
    depth: u32,
    /// `tree_index -> (value, next_index, next_value)`. Mirrors the
    /// linked-list structure that the jf IMT exposes, but in F1 + neptune.
    leaves: HashMap<u64, (F1, F1, F1)>,
    /// Counter for the next insertion slot.
    next_insert_index: u64,
    /// Precomputed all-zero subtree hash at each level.
    zero_hashes: Vec<F1>,
    constants: PoseidonConstants<F1, U2>,
    storage: S,
}

/// Result of a single nullifier insertion.
#[derive(Clone, Copy, Debug)]
pub struct NovaInsertionInfo {
    /// The nullifier that was inserted (zero for padding).
    pub nullifier: F1,
    /// Tree index of the low leaf, before this insertion.
    pub low_leaf_index: u64,
    /// Tree index of the newly-inserted leaf, after this insertion.
    /// `0` for padding (no real insertion happened).
    pub new_leaf_index: u64,
}

/// Convert an `F1` field element that represents a small non-negative
/// `u64` (e.g. a tree index) to `u64`. Returns 0 if the field element is
/// zero. This is the inverse of `F1::from(u64)`.
fn f1_to_u64(v: F1) -> u64 {
    let bytes = v.to_repr();
    let arr: [u8; 8] = bytes.as_ref()[..8].try_into().expect("F1 repr >= 8 bytes");
    u64::from_le_bytes(arr)
}

impl<S: NullifierTreeStorage> NeptuneIMT<S> {
    /// Create a new IMT with the canonical zero leaf at index 0.
    pub fn new(depth: u32, mut storage: S) -> Self {
        assert!((depth as u32) < 64, "tree depth must fit in u64 addressing");
        let constants = poseidon_constants::<F1>();
        let mut zero_hashes = vec![F1::ZERO; depth as usize + 1];
        for i in 1..=depth as usize {
            zero_hashes[i] =
                poseidon_hash2_native(&constants, zero_hashes[i - 1], zero_hashes[i - 1]);
        }

        let zero_leaf_hash = poseidon_hash3_native(&constants, F1::ZERO, F1::ZERO, F1::ZERO);

        let mut nodes: HashMap<(u32, u64), F1> = HashMap::new();
        // Insert the zero leaf at index 0.
        nodes.insert((0u32, 0u64), zero_leaf_hash);
        // Walk the path from the zero leaf to the root, persisting each
        // node.
        let mut idx = 0u64;
        for level in 0..depth {
            let is_right = idx & 1 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = zero_hashes[level as usize];
            let current = nodes[&(level, idx)];
            let parent_idx = idx / 2;
            let (left, right) = if is_right {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let parent_hash = poseidon_hash2_native(&constants, left, right);
            nodes.insert((level + 1, parent_idx), parent_hash);
            idx = parent_idx;
        }

        for ((lvl, idx2), hash) in &nodes {
            storage.put_node(*lvl, *idx2, *hash);
        }

        let mut leaves = HashMap::new();
        leaves.insert(0u64, (F1::ZERO, F1::ZERO, F1::ZERO));
        let next_insert_index = 1u64;
        let root = nodes[&(depth, 0)];
        let meta = NullifierTreeMetadata {
            tree_height: depth,
            next_insert_index,
            root,
        };
        storage.save_metadata(&meta);
        // Also persist the zero leaf so it shows up in the leaf DB.
        let zero_leaf = NovaIndexedLeaf {
            value: F1::ZERO,
            index: 0,
            next_index: F1::ZERO,
            next_value: F1::ZERO,
        };
        storage.put_leaf(&zero_leaf);

        Self {
            depth,
            leaves,
            next_insert_index,
            zero_hashes,
            constants,
            storage,
        }
    }

    /// Hydrate an existing IMT from storage.
    pub fn load(storage: S) -> Option<Self> {
        let meta = storage.load_metadata()?;
        let depth = meta.tree_height;
        let constants = poseidon_constants::<F1>();
        let mut zero_hashes = vec![F1::ZERO; depth as usize + 1];
        for i in 1..=depth as usize {
            zero_hashes[i] =
                poseidon_hash2_native(&constants, zero_hashes[i - 1], zero_hashes[i - 1]);
        }
        // Re-hydrate the in-memory leaf map by walking the storage.
        let mut leaves = HashMap::new();
        for index in 0..meta.next_insert_index {
            if let Some(leaf) = storage.get_leaf_by_index(index) {
                leaves.insert(leaf.index, (leaf.value, leaf.next_index, leaf.next_value));
            }
        }
        Some(Self {
            depth,
            leaves,
            next_insert_index: meta.next_insert_index,
            zero_hashes,
            constants,
            storage,
        })
    }

    /// Take the storage out of the IMT, consuming it. Used by tests to
    /// round-trip through `load`.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Current root.
    pub fn root(&self) -> F1 {
        self.storage
            .get_node(self.depth, 0)
            .unwrap_or(self.zero_hashes[self.depth as usize])
    }

    /// Tree depth.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Counter for the next insertion slot.
    pub fn next_insert_index(&self) -> u64 {
        self.next_insert_index
    }

    /// Check whether the IMT contains a leaf at the given tree index.
    pub fn has_leaf(&self, tree_index: u64) -> bool {
        self.leaves.contains_key(&tree_index)
    }

    /// Get the leaf data `(value, next_index, next_value)` at a given
    /// tree index.
    pub fn get_leaf(&self, tree_index: u64) -> Option<(F1, F1, F1)> {
        self.leaves.get(&tree_index).copied()
    }

    fn get_node(&self, level: u32, index: u64) -> F1 {
        self.storage
            .get_node(level, index)
            .unwrap_or(self.zero_hashes[level as usize])
    }

    fn put_node(&mut self, level: u32, index: u64, hash: F1) {
        self.storage.put_node(level, index, hash);
    }

    fn flush_metadata(&mut self) {
        let meta = NullifierTreeMetadata {
            tree_height: self.depth,
            next_insert_index: self.next_insert_index,
            root: self.root(),
        };
        self.storage.save_metadata(&meta);
    }

    /// Build a non-inclusion witness for `nullifier`. The low leaf is
    /// found by walking the linked list in sorted order. Returns the
    /// low leaf and a witness that the Nova circuit can verify directly.
    pub fn get_non_inclusion_witness(
        &self,
        nullifier: F1,
    ) -> Result<(NovaIndexedLeaf, ImtNonInclusionWitness<F1>), IMTError> {
        if nullifier == F1::ZERO {
            return Err(IMTError::NullifierIsZero);
        }
        if self.storage.get_leaf_by_value(nullifier).is_some() {
            return Err(IMTError::NullifierExists(nullifier));
        }
        let low_leaf = self
            .storage
            .get_low_leaf(nullifier)
            .ok_or(IMTError::TreeIsEmpty)?;
        let low_leaf_tree_index = low_leaf.index;
        let (low_value, next_index, next_value) = self
            .leaves
            .get(&low_leaf_tree_index)
            .copied()
            .ok_or(IMTError::InconsistentLeafDB)?;
        let path = self.inclusion_path(low_leaf_tree_index);
        let witness = ImtNonInclusionWitness {
            nullifier,
            low_value,
            low_next_index: next_index,
            low_next_value: next_value,
            path,
        };
        Ok((low_leaf, witness))
    }

    /// Build a Merkle inclusion path for the leaf at `tree_index`.
    pub fn inclusion_path(&self, tree_index: u64) -> Vec<MerklePathHop<F1>> {
        let mut path = Vec::with_capacity(self.depth as usize);
        let mut idx = tree_index;
        for level in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = self.get_node(level, sibling_idx);
            path.push(MerklePathHop { sibling, is_right });
            idx /= 2;
        }
        path
    }

    /// Insert a nullifier, updating both the low leaf's next pointer
    /// and adding a new leaf. Returns the insertion info needed to
    /// build the per-step circuit witness.
    pub fn insert_nullifier(&mut self, nullifier: F1) -> Result<NovaInsertionInfo, IMTError> {
        if nullifier == F1::ZERO {
            return Err(IMTError::NullifierIsZero);
        }
        if self.storage.get_leaf_by_value(nullifier).is_some() {
            return Err(IMTError::NullifierExists(nullifier));
        }
        // 1. Find the low leaf.
        let low_leaf = self
            .storage
            .get_low_leaf(nullifier)
            .ok_or(IMTError::TreeIsEmpty)?;
        let low_leaf_tree_index = low_leaf.index;
        let low_value = low_leaf.value;
        let old_next_index = low_leaf.next_index;
        let old_next_value = low_leaf.next_value;

        // 2. Allocate a new tree index.
        let new_leaf_index = self.next_insert_index;
        self.next_insert_index += 1;

        // 3. Update the low leaf to point to the new leaf.
        self.leaves.insert(
            low_leaf_tree_index,
            (low_value, F1::from(new_leaf_index), nullifier),
        );
        let updated_low_hash = imt_leaf_hash_native(
            &self.constants,
            low_value,
            F1::from(new_leaf_index),
            nullifier,
        );
        self.rehash_subtree(low_leaf_tree_index, updated_low_hash);

        // 4. Insert the new leaf, inheriting the low leaf's old next pointer.
        self.leaves
            .insert(new_leaf_index, (nullifier, old_next_index, old_next_value));
        let new_leaf_hash =
            imt_leaf_hash_native(&self.constants, nullifier, old_next_index, old_next_value);
        self.rehash_subtree(new_leaf_index, new_leaf_hash);

        // 5. Persist the new and updated leaves to the leaf DB.
        let updated_low_leaf = NovaIndexedLeaf {
            value: low_value,
            index: low_leaf_tree_index,
            next_index: F1::from(new_leaf_index),
            next_value: nullifier,
        };
        self.storage.put_leaf(&updated_low_leaf);

        let new_leaf = NovaIndexedLeaf {
            value: nullifier,
            index: new_leaf_index,
            next_index: old_next_index,
            next_value: old_next_value,
        };
        self.storage.put_leaf(&new_leaf);

        // 6. Flush metadata.
        self.flush_metadata();

        Ok(NovaInsertionInfo {
            nullifier,
            low_leaf_index: low_leaf_tree_index,
            new_leaf_index,
        })
    }

    /// Re-hash the path from `(level=0, index=leaf_index)` up to the root,
    /// using `new_leaf_hash` as the value at level 0.
    fn rehash_subtree(&mut self, leaf_index: u64, new_leaf_hash: F1) {
        self.put_node(0, leaf_index, new_leaf_hash);
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = self.get_node(level, sibling_idx);
            let current = self.get_node(level, idx);
            let parent_idx = idx / 2;
            let (left, right) = if is_right {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let parent_hash = poseidon_hash2_native(&self.constants, left, right);
            self.put_node(level + 1, parent_idx, parent_hash);
            idx = parent_idx;
        }
    }
}

/// Errors that can be returned by the IMT API.
#[derive(Debug)]
pub enum IMTError {
    NullifierIsZero,
    NullifierExists(F1),
    TreeIsEmpty,
    InconsistentLeafDB,
}

impl std::fmt::Display for IMTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullifierIsZero => write!(f, "nullifier must be non-zero"),
            Self::NullifierExists(v) => write!(f, "nullifier already exists in tree: {v:?}"),
            Self::TreeIsEmpty => write!(f, "tree has no low leaf for the requested value"),
            Self::InconsistentLeafDB => write!(
                f,
                "leaf DB and node storage disagree on the leaf at the requested index"
            ),
        }
    }
}

impl std::error::Error for IMTError {}

// ---------------------------------------------------------------------------
// Initial z0 computation.
// ---------------------------------------------------------------------------

/// Compute the IVC initial state vector `z0` using neptune Poseidon.
///
/// Returns `[empty_commitment_root, imt_root_with_zero_leaf, empty_historic_root, 0]`.
///
/// The commitment and historic-root trees start empty (all-zero leaves,
/// depth 32). The nullifier IMT starts with one zero leaf at index 0. This
/// must match the tree state at the start of the first block (after DB
/// initialisation).
pub fn compute_initial_z0() -> Vec<F1> {
    let constants = poseidon_constants::<F1>();

    // Empty commitment tree root (all zero leaves, depth 32).
    let mut zh = F1::ZERO;
    for _ in 0..32 {
        zh = poseidon_hash2_native(&constants, zh, zh);
    }
    let empty_commitment_root = zh;

    // Nullifier IMT root with zero leaf at index 0.
    let imt: NeptuneIMT<InMemoryNullifierStorage> =
        NeptuneIMT::new(32, InMemoryNullifierStorage::new());
    let imt_root = imt.root();

    // Historic root tree: starts empty (all zero leaves) — same root as commitment tree.
    let historic_root = empty_commitment_root;

    vec![
        empty_commitment_root,
        imt_root,
        historic_root,
        F1::ZERO,
        F1::ZERO,
    ]
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::nova_v1::hash::{poseidon_constants, poseidon_hash3_native};
    use crate::proving::nova_v1::merkle::{compute_merkle_root_native, imt_leaf_hash_native};

    #[test]
    fn f1_hex_round_trips() {
        use ff::Field;
        // Zero, one, a hydrated-root-like value, and the empty-tree z0[1].
        let z0 = compute_initial_z0();
        let cases = [F1::ZERO, F1::ONE, z0[1], z0[2], F1::from(123456789u64)];
        for v in cases {
            let hex = f1_to_hex(&v);
            assert!(hex.starts_with("0x") && hex.len() == 66, "bad hex: {hex}");
            let back = f1_from_hex(&hex).expect("f1_from_hex must parse f1_to_hex output");
            assert_eq!(v, back, "round-trip mismatch for {hex}");
            // Unprefixed and left-pad-tolerant parsing must agree.
            let back2 = f1_from_hex(hex.trim_start_matches("0x")).unwrap();
            assert_eq!(v, back2);
        }
        // Short hex is left-padded, not rejected.
        assert_eq!(f1_from_hex("0x01").unwrap(), F1::ONE);
        // Over-long hex is rejected.
        assert!(f1_from_hex(&"f".repeat(65)).is_err());
    }

    // -- Commitment tree -----------------------------------------------------

    #[test]
    fn commitment_tree_empty_root_is_deterministic() {
        let t1 = NeptuneCommitmentTree::new(32, InMemoryCommitmentStorage::new());
        let t2 = NeptuneCommitmentTree::new(32, InMemoryCommitmentStorage::new());
        assert_eq!(t1.root(), t2.root());
        assert_ne!(t1.root(), F1::ZERO, "empty tree root must not be zero");
    }

    #[test]
    fn commitment_tree_append_produces_valid_inclusion_proof() {
        let mut tree = NeptuneCommitmentTree::new(4, InMemoryCommitmentStorage::new());
        for i in 0u64..8 {
            let (root_after, path) = tree.append(F1::from(i + 1));
            let constants = poseidon_constants::<F1>();
            let recomputed = compute_merkle_root_native(&constants, F1::from(i + 1), &path);
            assert_eq!(
                root_after, recomputed,
                "path must recompute to current root"
            );
            assert_eq!(root_after, tree.root());
        }
        assert_eq!(tree.leaf_count(), 8);
    }

    #[test]
    fn commitment_tree_load_hydrates_state() {
        // Build a tree, dump it, then load a fresh tree from the same
        // storage and verify the root and leaf count round-trip.
        let mut tree = NeptuneCommitmentTree::new(4, InMemoryCommitmentStorage::new());
        for i in 0u64..3 {
            tree.append(F1::from(i + 100));
        }
        let original_root = tree.root();
        let original_count = tree.leaf_count();
        let storage = tree.into_storage();
        let rehydrated = NeptuneCommitmentTree::load(storage).expect("load must succeed");
        assert_eq!(rehydrated.root(), original_root);
        assert_eq!(rehydrated.leaf_count(), original_count);
    }

    #[test]
    fn v2_poseidon_note_commitment_and_nullifier_are_opaque_field_elements() {
        let constants = poseidon_constants::<F1>();
        let v2_commitment = poseidon_hash3_native(
            &constants,
            F1::from(0x4e46325fu64),
            F1::from(0x70726564u64),
            F1::from(0x6173736574u64),
        );
        assert_ne!(v2_commitment, F1::ZERO);

        let mut commitment_tree = NeptuneCommitmentTree::new(4, InMemoryCommitmentStorage::new());
        let (commitment_root, commitment_path) = commitment_tree.append(v2_commitment);
        let recomputed_commitment_root =
            compute_merkle_root_native(&constants, v2_commitment, &commitment_path);
        assert_eq!(commitment_root, recomputed_commitment_root);
        assert_eq!(commitment_root, commitment_tree.root());
        assert_eq!(commitment_tree.leaf_count(), 1);

        let v2_nullifier = poseidon_hash3_native(
            &constants,
            F1::from(0x6e756c6cu64),
            v2_commitment,
            F1::from(0x7370656e64u64),
        );
        assert_ne!(v2_nullifier, F1::ZERO);

        let mut nullifier_imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        let old_nullifiers_root = nullifier_imt.root();
        let (low_leaf, non_inclusion) = nullifier_imt
            .get_non_inclusion_witness(v2_nullifier)
            .expect("fresh v2 nullifier must non-include");
        assert_eq!(low_leaf.value, F1::ZERO);
        assert_eq!(non_inclusion.nullifier, v2_nullifier);

        let low_leaf_hash = imt_leaf_hash_native(
            &constants,
            non_inclusion.low_value,
            non_inclusion.low_next_index,
            non_inclusion.low_next_value,
        );
        let recomputed_old_root =
            compute_merkle_root_native(&constants, low_leaf_hash, &non_inclusion.path);
        assert_eq!(old_nullifiers_root, recomputed_old_root);

        let insertion = nullifier_imt
            .insert_nullifier(v2_nullifier)
            .expect("opaque v2 nullifier must insert like any F1");
        assert_eq!(insertion.nullifier, v2_nullifier);
        assert_eq!(insertion.low_leaf_index, 0);
        assert_eq!(insertion.new_leaf_index, 1);

        let new_nullifiers_root = nullifier_imt.root();
        assert_ne!(old_nullifiers_root, new_nullifiers_root);

        let (updated_low_value, updated_low_next_index, updated_low_next_value) =
            nullifier_imt.get_leaf(insertion.low_leaf_index).unwrap();
        assert_eq!(updated_low_value, F1::ZERO);
        assert_eq!(updated_low_next_index, F1::from(insertion.new_leaf_index));
        assert_eq!(updated_low_next_value, v2_nullifier);
        let updated_low_hash = imt_leaf_hash_native(
            &constants,
            updated_low_value,
            updated_low_next_index,
            updated_low_next_value,
        );
        let updated_low_path = nullifier_imt.inclusion_path(insertion.low_leaf_index);
        assert_eq!(
            new_nullifiers_root,
            compute_merkle_root_native(&constants, updated_low_hash, &updated_low_path)
        );

        let (new_leaf_value, new_leaf_next_index, new_leaf_next_value) = nullifier_imt
            .get_leaf(insertion.new_leaf_index)
            .expect("inserted nullifier leaf must exist");
        assert_eq!(new_leaf_value, v2_nullifier);
        assert_eq!(new_leaf_next_index, non_inclusion.low_next_index);
        assert_eq!(new_leaf_next_value, non_inclusion.low_next_value);
        let new_leaf_hash = imt_leaf_hash_native(
            &constants,
            new_leaf_value,
            new_leaf_next_index,
            new_leaf_next_value,
        );
        let new_leaf_path = nullifier_imt.inclusion_path(insertion.new_leaf_index);
        assert_eq!(
            new_nullifiers_root,
            compute_merkle_root_native(&constants, new_leaf_hash, &new_leaf_path)
        );
    }

    // -- Nullifier IMT -------------------------------------------------------

    #[test]
    fn imt_zero_leaf_is_only_leaf_initially() {
        let imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        assert!(imt.has_leaf(0));
        assert!(!imt.has_leaf(1));
        assert_eq!(imt.next_insert_index(), 1);
    }

    #[test]
    fn imt_insert_then_witness_round_trip() {
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());

        let info = imt.insert_nullifier(F1::from(10u64)).unwrap();
        assert_eq!(info.low_leaf_index, 0);
        assert_eq!(info.new_leaf_index, 1);

        // Witness for 30 should be against low leaf at index 1 (value=10).
        let (low_leaf, witness) = imt.get_non_inclusion_witness(F1::from(30u64)).unwrap();
        assert_eq!(low_leaf.value, F1::from(10u64));
        assert_eq!(witness.low_value, F1::from(10u64));
        // The low leaf is at index 1 (value=10) and the next leaf is the
        // tail (0, 0). So low_next_index = 0, low_next_value = 0.
        assert_eq!(witness.low_next_index, F1::ZERO);
        assert_eq!(witness.low_next_value, F1::ZERO);

        // Recompute the root from the witness and verify it matches.
        let constants = poseidon_constants::<F1>();
        let low_leaf_hash = imt_leaf_hash_native(
            &constants,
            witness.low_value,
            witness.low_next_index,
            witness.low_next_value,
        );
        let recomputed = compute_merkle_root_native(&constants, low_leaf_hash, &witness.path);
        assert_eq!(
            recomputed,
            imt.root(),
            "witness must recompute to current root"
        );
    }

    #[test]
    fn imt_inserts_in_unsorted_order_keeps_linked_list_sorted() {
        // Insert in random order; the IMT must always find the correct
        // low leaf based on value.
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        // Insert 20 first (low leaf 0).
        let i1 = imt.insert_nullifier(F1::from(20u64)).unwrap();
        assert_eq!(i1.low_leaf_index, 0);
        // Insert 10 next (low leaf 0, because 0 < 10 < 20).
        let i2 = imt.insert_nullifier(F1::from(10u64)).unwrap();
        assert_eq!(i2.low_leaf_index, 0, "10's low leaf is 0, not 1");
    }

    #[test]
    fn imt_rejects_zero_nullifier() {
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        let r = imt.insert_nullifier(F1::ZERO);
        assert!(matches!(r, Err(IMTError::NullifierIsZero)));
    }

    #[test]
    fn imt_rejects_duplicate_nullifier() {
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        imt.insert_nullifier(F1::from(42u64)).unwrap();
        let r = imt.insert_nullifier(F1::from(42u64));
        assert!(matches!(r, Err(IMTError::NullifierExists(_))));
    }

    #[test]
    fn imt_linked_list_is_consistent_after_multiple_inserts() {
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        for v in [10u64, 20, 5, 30, 25] {
            imt.insert_nullifier(F1::from(v)).unwrap();
        }
        // Walk the linked list from the zero leaf and collect the
        // non-zero values. They should be in ascending order.
        let mut values = vec![];
        let mut current_index = f1_to_u64(imt.get_leaf(0).unwrap().1);
        while current_index != 0 {
            let (value, next_index, _next_value) = imt.get_leaf(current_index).unwrap();
            values.push(value);
            current_index = f1_to_u64(next_index);
        }
        assert_eq!(
            values,
            vec![
                F1::from(5u64),
                F1::from(10u64),
                F1::from(20u64),
                F1::from(25u64),
                F1::from(30u64),
            ]
        );
    }

    #[test]
    fn imt_load_rehydrates_from_storage() {
        let mut imt = NeptuneIMT::new(4, InMemoryNullifierStorage::new());
        imt.insert_nullifier(F1::from(5u64)).unwrap();
        imt.insert_nullifier(F1::from(15u64)).unwrap();
        let original_root = imt.root();
        let storage = imt.into_storage();
        let rehydrated = NeptuneIMT::load(storage).expect("load must succeed");
        assert_eq!(rehydrated.root(), original_root);
        assert_eq!(rehydrated.next_insert_index(), 3);
        assert!(rehydrated.has_leaf(0));
        assert!(rehydrated.has_leaf(1));
        assert!(rehydrated.has_leaf(2));
    }

    #[test]
    fn initial_z0_root_matches_fresh_imt() {
        let imt: NeptuneIMT<InMemoryNullifierStorage> =
            NeptuneIMT::new(32, InMemoryNullifierStorage::new());
        let z0 = compute_initial_z0();
        assert_eq!(
            z0[1],
            imt.root(),
            "z0[1] must match a fresh NeptuneIMT root"
        );
    }
}
