use blake3::Hash;

use super::Node;

/// A group of [`Node`] instances at the same location within the tree.
///
/// A page within an MST is a probabilistically sized structure, with varying
/// numbers of [`Node`] within. A page has a min/max key range defined by the
/// nodes within it, and the page hash acts as a content hash, describing the
/// state of the page and the nodes within it.
#[derive(Default)]
pub struct Page<K> {
    nodes: Vec<Node<K>>,
    level: u8,

    /// The cached hash in this page; the cumulation of the hashes of the
    /// sub-tree rooted at this page.
    tree_hash: Option<Hash>,
}
