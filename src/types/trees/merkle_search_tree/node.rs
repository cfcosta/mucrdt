use blake3::{Hash, Hasher};

/// Storage for a single key/value pair.
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
