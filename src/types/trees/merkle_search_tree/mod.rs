mod node;
mod page;

use std::marker::PhantomData;

use crate::prelude::*;

pub use {node::Node, page::Page};

/// An implementation of a Merkle Search Tree, as described in [Merkle Search Trees: Efficient
/// State-Based CRDTs in Open Networks](https://inria.hal.science/hal-02303490/document).
///
/// A Merkle Search Tree (MST) is a probabilistically sized structure, with varying numbers of
/// [`Node`] within. A page has a min/max key range defined by the nodes within it, and the page
/// hash acts as a content hash, describing the state of the page and the nodes within it.
///
/// The tree hash is the hash of the root page, and is used to verify the integrity of the tree.
///
/// This implementation is heavily inspired by the one from the [merkle-search-tree
/// crate](https://docs.rs/merkle-search-tree), with some changes:
///
/// * We enforce blake3 as the hashing algorithm for the whole tree.
pub struct MerkleSearchTree<K, V> {
    root: Page<K>,
    root_hash: Option<Hash>,

    _value_type: PhantomData<V>,
}

impl<K, V> MerkleSearchTree<K, V> {
    pub fn root_hash(&self) -> Option<Hash> {
        self.root_hash
    }

    pub fn root_page(&self) -> &Page<K> {
        &self.root
    }
}
