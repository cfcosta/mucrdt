use std::marker::PhantomData;

use blake3::Hash;

use crate::prelude::*;

/// An implementation of the Merkle Search Tree as described in [Merkle Search Trees: Efficient
/// State-Based CRDTs in Open Networks](https://inria.hal.science/hal-02303490/document).
///
/// This implementation is heavily inspired from the one at the [merkle-search-tree
/// crate](https://docs.rs/merkle-search-tree).
pub struct MerkleSearchTree<K, V: ToBytes> {
    root: Page<K>,
    _value_type: PhantomData<V>,
}

/// A group of [`Node`] instances at the same location within the tree.
///
/// A page within an MST is a probabilistically sized structure, with varying
/// numbers of [`Node`] within. A page has a min/max key range defined by the
/// nodes within it, and the page hash acts as a content hash, describing the
/// state of the page and the nodes within it.
pub struct Page<K> {
    nodes: Vec<Node<K>>,
    level: u8,
}

impl<K> Default for Page<K> {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            level: 0,
        }
    }
}

/// Storage of a single key/value pair.
///
/// Keys are stored immutably in the [`Node`], alongside the hash of a value
/// (and not the value itself).
pub struct Node<K> {
    key: K,
    value: Hash,

    /// A pointer to a page with a strictly lower tree level, and containing
    /// strictly smaller/less-than keys when compared to "key".
    lt_pointer: Option<Hash>,
}
