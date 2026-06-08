//! Binary Poseidon Merkle membership.
//!
//! Matches Nightfall's commitment tree shape: a binary tree where each
//! `MembershipProof` carries the leaf, its index, and a sibling path. Each
//! [`PathElement`] is one sibling plus a direction flag indicating whether the
//! sibling sits on the left (`sibling_on_left = true`, NF4
//! `HashWithThisNodeOnLeft`) or the right (`HashWithThisNodeOnRight`).
//!
//! A parent node is `Poseidon(left, right)`.

use crate::hash;

/// One step of a sibling path.
pub struct PathElement {
    /// The sibling node value at this level.
    pub sibling: Field,
    /// `true` if the sibling is the left child (current node is the right child).
    pub sibling_on_left: bool,
}

/// Hash the current node together with its sibling, respecting direction.
pub fn parent(node: Field, step: PathElement) -> Field {
    if step.sibling_on_left {
        hash::hash2(step.sibling, node)
    } else {
        hash::hash2(node, step.sibling)
    }
}

/// Recompute the Merkle root from a leaf and its sibling path.
pub fn compute_root<let DEPTH: u32>(leaf: Field, path: [PathElement; DEPTH]) -> Field {
    let mut node = leaf;
    for i in 0..DEPTH {
        node = parent(node, path[i]);
    }
    node
}

/// Abort unless `leaf` is a member of the tree with the given `root`.
pub fn assert_membership<let DEPTH: u32>(
    leaf: Field,
    root: Field,
    path: [PathElement; DEPTH],
) {
    assert(compute_root(leaf, path) == root, "merkle: membership proof failed");
}
