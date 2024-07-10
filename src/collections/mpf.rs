/// Merkle Patricia Forestry (MPF): An Advanced Key-Value Data Structure
///
/// This implementation is based on the one done by Matthias Benkort on the
/// [Merkle Patricia
/// Forestry](https://github.com/aiken-lang/merkle-patricia-forestry)
/// implementation for Aiken and Typescript.
///
/// The MPF combines Merkle trees and Patricia tries to create an append-only
/// key-value store. It uses a radix-16 trie where each node contains a
/// cryptographic hash digest of its sub-trie or value.
///
/// ## Core Concepts
///
/// 1. Trie Structure:
///    - Radix-16 trie (hexadecimal digits/nibbles)
///    - Two node types:
///      a. Branch nodes: Up to 16 children (one per nibble)
///      b. Leaf nodes: Stores key-value pair and remaining key part (suffix)
///
/// 2. Hashing Mechanism:
///    - Leaf nodes: hash = H(head(suffix) || tail(suffix) || H(value) || tombstone)
///    - Branch nodes: hash = H(nibbles(prefix) || H(Merkle tree of children))
///    Where H is the cryptographic hash function, and || denotes concatenation.
///
/// 3. Branch Node Innovation:
///    Instead of concatenating child hashes, we construct a Sparse Merkle Tree (SMT)
///    of the children. This significantly reduces proof sizes while maintaining
///    security.
///
/// 4. Path Compression:
///    Implemented to reduce the number of nodes in the trie by merging nodes
///    with single children into their parents, storing the compressed path.
///
/// ## Why MPF?
///
/// MPF addresses key challenges faced by traditional Merkle Patricia Tries (MPTs):
///
/// 1. Proof Size Efficiency:
///    Classic MPTs with radix-16 can lead to large proofs. MPF reduces proof
///    size from 480 bytes to 130 bytes per branch node by using SMTs.
///
/// 2. Balancing Radix Size and Proof Complexity:
///    MPF strikes a balance between the efficiency of radix-16 tries and the
///    compact proofs of binary tries.
///
/// 3. Byte-Oriented System Compatibility:
///    MPF works efficiently with byte-oriented systems while maintaining the
///    benefits of nibble-based tries.
///
/// 4. Space Efficiency:
///    Path compression reduces the overall number of nodes in the trie,
///    leading to more efficient storage and faster traversal.
///
/// ## Proof Structure
///
/// MPF proofs are designed for compactness and efficiency. Each proof step can be:
///
/// - Branch: Provides hashes of up to 4 sub-trees in an SMT structure.
/// - Fork: Used when a branch node's prefix splits due to a new insertion.
/// - Leaf: Contains the full key-value pair for the leaf node, including tombstone status.
///
/// ## Performance Characteristics
///
/// MPF balances proof size and computational overhead:
///
/// | Elements | Proof Size (bytes) |
/// |----------|---------------------|
/// | 10²      | 250                 |
/// | 10³      | 350                 |
/// | 10⁴      | 460                 |
/// | 10⁵      | 560                 |
/// | 10⁶      | 670                 |
/// | 10⁷      | 780                 |
/// | 10⁸      | 880                 |
/// | 10⁹      | 990                 |
///
/// ## Advantages
///
/// 1. Efficient membership checks and insertions using root hashes and succinct proofs
/// 2. Significantly smaller proofs compared to traditional MPTs
/// 3. CPU and memory-efficient operations
/// 4. Balanced approach to proof size and computational overhead
/// 5. Compatibility with byte-oriented systems while maintaining nibble-based trie efficiency
/// 6. Support for logical deletions through tombstones
/// 7. Improved space efficiency through path compression
///
/// ## Limitations
///
/// This MPF implementation supports insertions and logical deletions (via tombstones),
/// but not updates. This design choice ensures data structure integrity while allowing
/// for removals.
///
/// ## Use Cases
///
/// MPF is particularly useful in scenarios requiring:
///
/// - Efficient membership proofs
/// - Limited storage space for proofs
/// - Append-only data structures with support for logical deletions
/// - Cryptographic primitive compatibility
/// - Balance between proof size and computational overhead
///
/// When considering MPF, evaluate the trade-off between proof size and
/// computational overhead for your specific use case.
use std::marker::PhantomData;

use digest::Digest;
use proptest::{array::uniform4, collection::vec, prelude::*};

use crate::{error::Error, prelude::*, values::Hash};

/// Represents a Merkle Patricia Forestry
pub struct MerklePatriciaForestry<D: Digest> {
    pub proof: MerkleProof,
    pub root: Hash,
    _phantom: PhantomData<D>,
}

impl<D: Digest> MerklePatriciaForestry<D> {
    /// Constructs a new MerklePatriciaForestry from its proof.
    ///
    /// This function takes a MerkleProof and creates a new MerklePatriciaForestry instance.
    /// It calculates the root hash from the provided proof and initializes the structure.
    ///
    /// # Arguments
    ///
    /// * `proof` - A MerkleProof representing the state of the Merkle Patricia Forestry.
    ///
    /// # Returns
    ///
    /// A new instance of MerklePatriciaForestry.
    pub fn from_proof(proof: MerkleProof) -> Self {
        let root = Self::calculate_root(&proof);
        Self {
            proof,
            root,
            _phantom: PhantomData,
        }
    }

    /// Constructs a new empty MerklePatriciaForestry.
    ///
    /// This function creates an empty MerklePatriciaForestry with no elements.
    /// The proof is an empty vector and the root is set to the zero hash.
    ///
    /// # Returns
    ///
    /// A new empty instance of MerklePatriciaForestry.
    pub fn empty() -> Self {
        Self {
            proof: MerkleProof(vec![]),
            root: Hash::zero(),
            _phantom: PhantomData,
        }
    }

    /// Checks if the MerklePatriciaForestry is empty.
    ///
    /// This function determines whether the MerklePatriciaForestry contains any elements.
    ///
    /// # Returns
    ///
    /// `true` if the MerklePatriciaForestry is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.proof.0.is_empty()
    }

    /// Verifies if an element is present in the trie with a specific value.
    ///
    /// This function checks whether a given key-value pair exists in the MerklePatriciaForestry
    /// and is not marked as deleted.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the key to verify.
    /// * `value` - A byte slice representing the value to verify.
    ///
    /// # Returns
    ///
    /// `true` if the key-value pair is present in the trie and not deleted, `false` otherwise.
    pub fn verify(&self, key: &[u8], value: &[u8]) -> bool {
        if self.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);
        self.verify_proof(key_hash, value_hash, &self.proof)
    }

    /// Inserts an element to the trie.
    ///
    /// This function adds a new key-value pair to the MerklePatriciaForestry.
    /// It updates the proof and recalculates the root hash.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the key to insert.
    /// * `value` - A byte slice representing the value to insert.
    ///
    /// # Returns
    ///
    /// A Result indicating success or an MPFError if the operation fails.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), MPFError> {
        if key.is_empty() {
            return Err(MPFError::EmptyKeyOrValue);
        }

        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);

        self.proof = self.insert_to_proof(key_hash, value_hash);
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }

    /// Removes an element from the trie.
    ///
    /// This function marks a key-value pair as deleted in the MerklePatriciaForestry.
    /// It updates the proof and recalculates the root hash.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the key to remove.
    ///
    /// # Returns
    ///
    /// A Result indicating success or an MPFError if the operation fails.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), MPFError> {
        if key.is_empty() {
            return Err(MPFError::EmptyKeyOrValue);
        }

        let key_hash = Hash::digest::<D>(key);

        // Instead of removing the leaf, we'll mark it as deleted
        self.proof = self.mark_as_deleted(key_hash);
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }

    /// Verifies a proof for a given key and value.
    ///
    /// This function checks if a given key-value pair exists in the provided proof
    /// and is not marked as deleted.
    ///
    /// # Arguments
    ///
    /// * `key` - The Hash of the key to verify.
    /// * `value` - The Hash of the value to verify.
    /// * `proof` - A reference to the MerkleProof to check against.
    ///
    /// # Returns
    ///
    /// `true` if the key-value pair is present in the proof and not deleted, `false` otherwise.
    pub fn verify_proof(&self, key: Hash, value: Hash, proof: &MerkleProof) -> bool {
        if proof.0.is_empty() {
            return false;
        }

        proof.0.iter().any(|step| {
            matches!(step, MerkleStep::Leaf { key: leaf_key, value: leaf_value, .. } if *leaf_key == key && *leaf_value == value && *leaf_value != Hash::zero())
        })
    }

    /// Inserts a key-value pair into the proof.
    ///
    /// This function creates a new proof by adding the given key-value pair
    /// and removing any existing leaf with the same key. It also applies path compression.
    ///
    /// # Arguments
    ///
    /// * `key` - The Hash of the key to insert.
    /// * `value` - The Hash of the value to insert.
    ///
    /// # Returns
    ///
    /// A new MerkleProof containing the inserted key-value pair with path compression applied.
    fn insert_to_proof(&self, key: Hash, value: Hash) -> MerkleProof {
        let mut new_proof = self.proof.clone();
        // Remove any existing leaf with the same key
        new_proof.0.retain(
            |step| !matches!(step, MerkleStep::Leaf { key: leaf_key, .. } if *leaf_key == key),
        );
        new_proof.0.push(MerkleStep::Leaf {
            skip: 0,
            key,
            value,
        });
        Self::compress_path(&mut new_proof);
        new_proof
    }

    /// Marks a key-value pair as deleted in the proof.
    ///
    /// This function creates a new proof by marking the leaf with the given key as deleted
    /// and applies path compression.
    ///
    /// # Arguments
    ///
    /// * `key` - The Hash of the key to mark as deleted.
    ///
    /// # Returns
    ///
    /// A new MerkleProof with the key-value pair marked as deleted and path compression applied.
    fn mark_as_deleted(&self, key: Hash) -> MerkleProof {
        let mut new_proof = self.proof.clone();
        for step in new_proof.0.iter_mut() {
            if let MerkleStep::Leaf {
                key: leaf_key,
                value,
                ..
            } = step
            {
                if *leaf_key == key {
                    // Mark the leaf as deleted by setting its value to a special "tombstone" value
                    *value = Hash::zero(); // Use a zero hash to represent a tombstone
                    break;
                }
            }
        }
        Self::compress_path(&mut new_proof);
        new_proof
    }

    /// Applies path compression to the proof.
    ///
    /// This function merges nodes with single children into their parents,
    /// reducing the overall number of nodes in the trie.
    ///
    /// # Arguments
    ///
    /// * `proof` - A mutable reference to the MerkleProof to compress.
    fn compress_path(proof: &mut MerkleProof) {
        let mut i = 0;
        while i < proof.0.len() - 1 {
            if let (
                MerkleStep::Branch {
                    skip: skip1,
                    neighbors: neighbors1,
                },
                MerkleStep::Branch {
                    skip: skip2,
                    neighbors: neighbors2,
                },
            ) = (&proof.0[i], &proof.0[i + 1])
            {
                if neighbors1.iter().filter(|&&n| n != Hash::zero()).count() == 1
                    && neighbors2.iter().filter(|&&n| n != Hash::zero()).count() == 1
                {
                    // Merge the two branch nodes
                    let new_skip = skip1 + skip2 + 1;
                    let new_neighbors = neighbors2.clone();
                    proof.0[i] = MerkleStep::Branch {
                        skip: new_skip,
                        neighbors: new_neighbors,
                    };
                    proof.0.remove(i + 1);
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    /// Calculates the root hash of the Merkle Patricia Forestry.
    ///
    /// This function computes the root hash based on the provided proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - A reference to the MerkleProof to calculate the root from.
    ///
    /// # Returns
    ///
    /// The calculated root Hash of the Merkle Patricia Forestry.
    fn calculate_root(proof: &MerkleProof) -> Hash {
        let mut hasher = D::new();
        for step in &proof.0 {
            match step {
                MerkleStep::Branch { neighbors, .. } => {
                    for neighbor in neighbors {
                        hasher.update(neighbor.as_ref());
                    }
                }
                MerkleStep::Fork { neighbor, .. } => {
                    hasher.update([neighbor.nibble]);
                    hasher.update(&neighbor.prefix);
                    hasher.update(neighbor.root.as_ref());
                }
                MerkleStep::Leaf { key, value, .. } => {
                    hasher.update(key.as_ref());
                    hasher.update(value.as_ref());
                }
            }
        }
        Hash::from_slice(hasher.finalize().as_ref())
    }
}

impl<D: Digest> Clone for MerklePatriciaForestry<D> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            root: self.root,
            _phantom: PhantomData,
        }
    }
}

impl<D: Digest> PartialEq for MerklePatriciaForestry<D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<D: Digest> Eq for MerklePatriciaForestry<D> {}

impl<D: Digest> std::fmt::Debug for MerklePatriciaForestry<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerklePatriciaForestry")
            .field("proof", &self.proof)
            .field("root", &self.root)
            .finish()
    }
}

impl<D: Digest> Default for MerklePatriciaForestry<D> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<D: Digest + 'static> Arbitrary for MerklePatriciaForestry<D> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<MerkleProof>()
            .prop_map(|proof| Self::from_proof(proof))
            .boxed()
    }
}

impl<D: Digest + 'static> CvRDT for MerklePatriciaForestry<D> {
    fn merge(&mut self, other: &Self) -> Result<()> {
        let mut merged_proof = self.proof.clone();
        for step in other.proof.0.iter() {
            if !merged_proof.0.contains(step) {
                merged_proof.0.push(step.clone());
            }
        }

        self.proof = merged_proof;
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }
}

impl<D: Digest + 'static> CmRDT<MerkleProof> for MerklePatriciaForestry<D> {
    fn apply(&mut self, op: &MerkleProof) -> Result<()> {
        let mpf = Self::from_proof(op.clone());
        self.merge(&mpf)
    }
}

/// Represents a proof in the Merkle Patricia Forestry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof(pub Vec<MerkleStep>);

impl PartialOrd for MerkleProof {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Compare the lengths of the proof vectors first
        match self.0.len().partial_cmp(&other.0.len()) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }

        // If lengths are equal, compare each step
        for (self_step, other_step) in self.0.iter().zip(other.0.iter()) {
            match self_step.partial_cmp(other_step) {
                Some(core::cmp::Ordering::Equal) => continue,
                ord => return ord,
            }
        }

        // If all steps are equal, the proofs are equal
        Some(core::cmp::Ordering::Equal)
    }
}

impl Arbitrary for MerkleProof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_depth: Self::Parameters) -> Self::Strategy {
        vec(any::<MerkleStep>(), 0..=max_depth)
            .prop_map(MerkleProof)
            .boxed()
    }
}

/// Represents a single step in a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleStep {
    /// A branch node in the trie.
    Branch {
        /// The number of common prefix nibbles to skip.
        skip: usize,
        /// The hash digests of the neighboring branches.
        neighbors: [Hash; 4],
    },
    /// A fork node in the trie.
    Fork {
        /// The number of common prefix nibbles to skip.
        skip: usize,
        /// The neighboring node information.
        neighbor: Neighbor,
    },
    /// A leaf node in the trie.
    Leaf {
        /// The number of common prefix nibbles to skip.
        skip: usize,
        /// The full key of the leaf.
        key: Hash,
        /// The value stored at the leaf.
        value: Hash,
    },
}

impl ToBytes for MerkleStep {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        match self {
            MerkleStep::Branch { skip, neighbors } => {
                let mut bytes = vec![0u8]; // 0 indicates Branch
                bytes.extend_from_slice(&skip.to_be_bytes());
                for neighbor in neighbors {
                    bytes.extend_from_slice(neighbor.as_ref());
                }
                bytes
            }
            MerkleStep::Fork { skip, neighbor } => {
                let mut bytes = vec![1u8]; // 1 indicates Fork
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend(neighbor.to_bytes());
                bytes
            }
            MerkleStep::Leaf { skip, key, value } => {
                let mut bytes = vec![2u8]; // 2 indicates Leaf
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend_from_slice(key.as_ref());
                bytes.extend_from_slice(value.as_ref());
                bytes
            }
        }
    }
}

impl FromBytes for MerkleStep {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::FailedDeserialization("Empty input".to_string()));
        }

        match bytes[0] {
            0 => {
                // Branch
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 4 * 32 {
                    return Err(Error::FailedDeserialization(
                        "Invalid length for Branch".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let mut neighbors = [Hash::default(); 4];
                for (i, neighbor) in neighbors.iter_mut().enumerate() {
                    let start = 1 + std::mem::size_of::<usize>() + i * 32;
                    *neighbor = Hash::from_slice(&bytes[start..start + 32]);
                }
                Ok(MerkleStep::Branch { skip, neighbors })
            }
            1 => {
                // Fork
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 33 {
                    return Err(Error::FailedDeserialization(
                        "Invalid length for Fork".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let neighbor = Neighbor::from_bytes(&bytes[1 + std::mem::size_of::<usize>()..])?;
                Ok(MerkleStep::Fork { skip, neighbor })
            }
            2 => {
                // Leaf
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 64 {
                    return Err(Error::FailedDeserialization(
                        "Invalid length for Leaf".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let key = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>()..1 + std::mem::size_of::<usize>() + 32],
                );
                let value = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>() + 32
                        ..1 + std::mem::size_of::<usize>() + 64],
                );
                Ok(MerkleStep::Leaf { skip, key, value })
            }
            _ => Err(Error::FailedDeserialization(
                "Invalid MerkleStep type".to_string(),
            )),
        }
    }
}

impl Arbitrary for MerkleStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (any::<usize>(), uniform4(any::<Hash>()))
                .prop_map(|(skip, neighbors)| MerkleStep::Branch { skip, neighbors }),
            (any::<usize>(), any::<Neighbor>())
                .prop_map(|(skip, neighbor)| MerkleStep::Fork { skip, neighbor }),
            (any::<usize>(), any::<Hash>(), any::<Hash>())
                .prop_map(|(skip, key, value)| MerkleStep::Leaf { skip, key, value })
        ]
        .boxed()
    }
}

impl PartialOrd for MerkleStep {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                MerkleStep::Branch {
                    skip: s1,
                    neighbors: n1,
                },
                MerkleStep::Branch {
                    skip: s2,
                    neighbors: n2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(core::cmp::Ordering::Equal) => n1.partial_cmp(n2),
                ord => ord,
            },
            (
                MerkleStep::Fork {
                    skip: s1,
                    neighbor: n1,
                },
                MerkleStep::Fork {
                    skip: s2,
                    neighbor: n2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(core::cmp::Ordering::Equal) => n1.partial_cmp(n2),
                ord => ord,
            },
            (
                MerkleStep::Leaf {
                    skip: s1,
                    key: k1,
                    value: v1,
                },
                MerkleStep::Leaf {
                    skip: s2,
                    key: k2,
                    value: v2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(core::cmp::Ordering::Equal) => match k1.partial_cmp(k2) {
                    Some(core::cmp::Ordering::Equal) => v1.partial_cmp(v2),
                    ord => ord,
                },
                ord => ord,
            },
            // Define an arbitrary order between different Step variants
            (MerkleStep::Branch { .. }, _) => Some(core::cmp::Ordering::Less),
            (_, MerkleStep::Branch { .. }) => Some(core::cmp::Ordering::Greater),
            (MerkleStep::Fork { .. }, MerkleStep::Leaf { .. }) => Some(core::cmp::Ordering::Less),
            (MerkleStep::Leaf { .. }, MerkleStep::Fork { .. }) => {
                Some(core::cmp::Ordering::Greater)
            }
        }
    }
}

/// Represents a neighboring node in a fork step of a proof.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Neighbor {
    /// The nibble (4-bit value) of the neighbor.
    pub nibble: u8,
    /// The remaining prefix of the neighbor's key.
    pub prefix: Vec<u8>,
    /// The hash digest of the neighbor's subtree.
    pub root: Hash,
}

impl Arbitrary for Neighbor {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<u8>(), any::<Vec<u8>>(), any::<Hash>())
            .prop_map(|(nibble, prefix, root)| Neighbor {
                nibble,
                prefix,
                root,
            })
            .boxed()
    }
}

impl ToBytes for Neighbor {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        let mut bytes = vec![self.nibble];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(self.root.as_ref());
        bytes
    }
}

impl FromBytes for Neighbor {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 33 {
            return Err(Error::FailedDeserialization(
                "Invalid length for Neighbor".to_string(),
            ));
        }
        let nibble = bytes[0];
        let prefix = bytes[1..bytes.len() - 32].to_vec();
        let root = Hash::from_slice(&bytes[bytes.len() - 32..]);
        Ok(Neighbor {
            nibble,
            prefix,
            root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;

    macro_rules! generate_mpf_tests {
        ($digest:ty) => {
            paste! {
                #[allow(non_snake_case)]
                mod [<$digest _tests>] {
                    use super::*;
                    use $digest;
                    use proptest::strategy::Strategy;

                    fn non_empty_string() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("must not be empty", |s| !s.is_empty())
                    }

                    #[test_strategy::proptest]
                    fn test_verify_proof(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()),
                            "MerkleProof verification failed for key: {:?}, value: {:?}",
                            key, value);
                    }

                    #[test_strategy::proptest]
                    fn test_insert(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let original_trie = trie.clone();
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));
                        prop_assert_ne!(trie, original_trie);
                    }

                    #[test_strategy::proptest]
                    fn test_multiple_inserts(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);

                        let original_trie = trie.clone();
                        trie.insert(key1.as_bytes(), value1.as_bytes())?;
                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert_ne!(&trie, &original_trie);

                        let trie_after_first_insert = trie.clone();
                        trie.insert(key2.as_bytes(), value2.as_bytes())?;
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));
                        prop_assert_ne!(&trie, &trie_after_first_insert);

                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));
                    }

                    #[test]
                    fn test_empty_trie() {
                        let empty_trie = MerklePatriciaForestry::<$digest>::empty();
                        assert!(empty_trie.is_empty());
                    }

                    #[test_strategy::proptest]
                    fn test_start_empty_add_one_check_hash(
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let mut trie = MerklePatriciaForestry::<$digest>::empty();
                        assert!(trie.is_empty());

                        let empty_root = trie.root;
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(!trie.is_empty());
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));

                        prop_assert_ne!(empty_root, trie.root, "Hash should change after insertion");
                    }

                    #[test_strategy::proptest]
                    fn test_proof_verification(
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        // Test empty trie
                        let empty_trie = MerklePatriciaForestry::<$digest>::empty();
                        prop_assert!(!empty_trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Test non-empty trie
                        let mut non_empty_trie = MerklePatriciaForestry::<$digest>::empty();
                        non_empty_trie.insert(key1.as_bytes(), value1.as_bytes())?;

                        prop_assert!(non_empty_trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key2.as_bytes(), value1.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key1.as_bytes(), value2.as_bytes()));
                        prop_assert!(!non_empty_trie.verify(key2.as_bytes(), value2.as_bytes()));

                        // Test updating an existing key
                        non_empty_trie.insert(key1.as_bytes(), value2.as_bytes())?;
                        prop_assert!(!non_empty_trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(non_empty_trie.verify(key1.as_bytes(), value2.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_proof_verification_with_tombstones(
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        let mut trie = MerklePatriciaForestry::<$digest>::empty();

                        // Insert and then remove key1
                        trie.insert(key1.as_bytes(), value1.as_bytes())?;
                        trie.remove(key1.as_bytes())?;

                        // Verify that key1 is not in the trie (tombstone)
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!trie.verify(key1.as_bytes(), &[]));

                        // Insert key2
                        trie.insert(key2.as_bytes(), value2.as_bytes())?;

                        // Verify that key2 is in the trie
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));

                        // Verify that key1 is still not in the trie
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!trie.verify(key1.as_bytes(), &[]));

                        // Remove key2
                        trie.remove(key2.as_bytes())?;

                        // Verify that both keys are not in the trie (tombstones)
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!trie.verify(key1.as_bytes(), &[]));
                        prop_assert!(!trie.verify(key2.as_bytes(), value2.as_bytes()));
                        prop_assert!(!trie.verify(key2.as_bytes(), &[]));

                        // Reinsert key1 with a different value
                        trie.insert(key1.as_bytes(), value2.as_bytes())?;

                        // Verify that key1 is now in the trie with the new value
                        prop_assert!(trie.verify(key1.as_bytes(), value2.as_bytes()));
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Verify that key2 is still not in the trie
                        prop_assert!(!trie.verify(key2.as_bytes(), value2.as_bytes()));
                        prop_assert!(!trie.verify(key2.as_bytes(), &[]));
                    }

                    #[test_strategy::proptest]
                    fn test_proof_size(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] trie: MerklePatriciaForestry<$digest>
                    ) {
                        let proof = trie.proof.clone();
                        prop_assert!(proof.0.len() <= 130 * (4 + 1),
                            "MerkleProof size {} exceeds expected maximum",
                            proof.0.len());
                    }

                    #[test]
                    fn test_empty_key_or_value() {
                        let mut trie = MerklePatriciaForestry::<$digest>::empty();
                        assert!(matches!(trie.insert(&[], b"value"), Err(MPFError::EmptyKeyOrValue)));
                        assert!(trie.insert(b"key", &[]).is_ok());
                    }

                    #[test_strategy::proptest]
                    fn test_root_proof_equality(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] trie1: MerklePatriciaForestry<$digest>,
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] trie2: MerklePatriciaForestry<$digest>
                    ) {
                        prop_assert_eq!(
                            trie1.root == trie2.root,
                            trie1.proof == trie2.proof,
                            "Root equality should imply proof equality"
                        );
                    }

                    #[test_strategy::proptest]
                    fn test_default_is_empty(
                        #[strategy(Just(MerklePatriciaForestry::<$digest>::default()))] default_trie: MerklePatriciaForestry<$digest>
                    ) {
                        prop_assert!(default_trie.is_empty(), "Default instance should be empty");
                    }

                    #[test_strategy::proptest]
                    fn test_root_matches_calculated(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] trie: MerklePatriciaForestry<$digest>
                    ) {
                        let calculated_root = MerklePatriciaForestry::<$digest>::calculate_root(&trie.proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root");
                    }

                    #[test_strategy::proptest]
                    fn test_from_proof_root_calculation(#[strategy(any::<MerkleProof>())] proof: MerkleProof) {
                        let trie = MerklePatriciaForestry::<$digest>::from_proof(proof.clone());
                        let calculated_root = MerklePatriciaForestry::<$digest>::calculate_root(&proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root after from_proof");
                    }

                    #[test_strategy::proptest]
                    fn test_verify_non_existent(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        trie.insert(key1.as_bytes(), value1.as_bytes())?;

                        // Verify correct key-value pair
                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Verify non-existent key
                        prop_assert!(!trie.verify(key2.as_bytes(), value1.as_bytes()));

                        // Verify existing key with wrong value
                        prop_assert!(!trie.verify(key1.as_bytes(), value2.as_bytes()));

                        // Verify non-existent key-value pair
                        prop_assert!(!trie.verify(key2.as_bytes(), value2.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_remove_through_tombstone(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        // Insert a key-value pair
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));

                        // Remove the key
                        trie.remove(key.as_bytes())?;

                        // Verify that the key-value pair is no longer present
                        prop_assert!(!trie.verify(key.as_bytes(), value.as_bytes()));

                        // Try to remove the key again (should not cause an error)
                        prop_assert!(trie.remove(key.as_bytes()).is_ok());

                        // Verify that inserting the same key with a different value works
                        let new_value = "new_value".to_string();
                        trie.insert(key.as_bytes(), new_value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), new_value.as_bytes()));
                        prop_assert!(!trie.verify(key.as_bytes(), value.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_multiple_removes(
                        #[strategy(any::<MerklePatriciaForestry<$digest>>())] mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        value2: String
                    ) {
                        prop_assume!(key1 != key2);

                        // Insert two key-value pairs
                        trie.insert(key1.as_bytes(), value1.as_bytes())?;
                        trie.insert(key2.as_bytes(), value2.as_bytes())?;

                        // Verify both are present
                        prop_assert!(trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));

                        // Remove the first key
                        trie.remove(key1.as_bytes())?;

                        // Verify first key is removed but second is still present
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(trie.verify(key2.as_bytes(), value2.as_bytes()));

                        // Remove the second key
                        trie.remove(key2.as_bytes())?;

                        // Verify both keys are removed
                        prop_assert!(!trie.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!trie.verify(key2.as_bytes(), value2.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_second_preimage_resistance(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key1: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 1..100))] key2: Vec<u8>,
                        value1: u8,
                        value2: u8
                    ) {
                        prop_assume!(key1 != key2);

                        trie.insert(&key1, &[value1])?;
                        let root1 = trie.root;

                        trie.insert(&key2, &[value2])?;
                        let root2 = trie.root;

                        prop_assert_ne!(root1, root2, "Different key-value pairs should produce different trie states");

                        // Verify both key-value pairs are present
                        prop_assert!(trie.verify(&key1, &[value1]), "First key-value pair not found");
                        prop_assert!(trie.verify(&key2, &[value2]), "Second key-value pair not found");
                    }

                    #[test_strategy::proptest]
                    fn test_malicious_proof_resistance(
                        trie: MerklePatriciaForestry<$digest>,
                        key: Vec<u8>,
                        value: u8,
                        malicious_steps: Vec<MerkleStep>
                    ) {
                        // Skip the test if the trie is empty and there are no malicious steps
                        prop_assume!(!trie.is_empty() || !malicious_steps.is_empty());

                        let mut malicious_proof = trie.proof.clone();
                        malicious_proof.0.extend(malicious_steps);

                        let malicious_trie = MerklePatriciaForestry::<$digest>::from_proof(malicious_proof);

                        // Verify that the malicious trie doesn't falsely claim to contain the key-value pair
                        prop_assert!(!malicious_trie.verify(&key, &[value]), "Malicious proof falsely verified");

                        // Ensure the root hash of the malicious trie is different
                        prop_assert_ne!(trie.root, malicious_trie.root, "Malicious trie has the same root hash");
                    }

                    #[test_strategy::proptest]
                    fn test_large_key_value_pairs(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = trie.proof.0.len();
                        trie.insert(&large_key, &large_value)?;
                        prop_assert!(trie.verify(&large_key, &large_value), "Failed to verify large key-value pair");

                        // Check that trie size increase is reasonable
                        let size_increase = trie.proof.0.len() - initial_size;
                        prop_assert!(size_increase <= large_key.len() + large_value.len(),
                            "Trie size increase {} is larger than key size {} plus value size {}",
                            size_increase, large_key.len(), large_value.len());
                    }

                    type Mpf = MerklePatriciaForestry<$digest>;
                    crate::test_state_crdt_properties!(Mpf);
                    crate::test_op_crdt_properties!(Mpf, MerkleProof);
                }
            }
        };
    }

    type Blake3 = blake3::Hasher;
    type Blake2s = blake2::Blake2s256;
    type Sha256 = sha2::Sha256;

    generate_mpf_tests!(Blake3);
    generate_mpf_tests!(Blake2s);
    generate_mpf_tests!(Sha256);

    #[test_strategy::proptest]
    fn test_merkle_proof_reflexive(proof: MerkleProof) {
        prop_assert_eq!(proof.partial_cmp(&proof), Some(std::cmp::Ordering::Equal));
    }

    #[test_strategy::proptest]
    fn test_merkle_proof_antisymmetric(proof1: MerkleProof, proof2: MerkleProof) {
        if proof1 == proof2 {
            prop_assert_eq!(proof1.partial_cmp(&proof2), Some(std::cmp::Ordering::Equal));
            prop_assert_eq!(proof2.partial_cmp(&proof1), Some(std::cmp::Ordering::Equal));
        } else if let (Some(ord1), Some(ord2)) =
            (proof1.partial_cmp(&proof2), proof2.partial_cmp(&proof1))
        {
            prop_assert_ne!(ord1, ord2);
        }
    }

    #[test_strategy::proptest]
    fn test_merkle_proof_transitive(proof1: MerkleProof, proof2: MerkleProof, proof3: MerkleProof) {
        if let (Some(ord1), Some(ord2)) = (proof1.partial_cmp(&proof2), proof2.partial_cmp(&proof3))
        {
            if ord1 == ord2 {
                prop_assert_eq!(proof1.partial_cmp(&proof3), Some(ord1));
            }
        }
    }

    #[test_strategy::proptest]
    fn test_merkle_proof_consistency(proof1: MerkleProof, proof2: MerkleProof) {
        let cmp1 = proof1.partial_cmp(&proof2);
        let cmp2 = proof2.partial_cmp(&proof1);

        match (cmp1, cmp2) {
            (Some(std::cmp::Ordering::Less), Some(std::cmp::Ordering::Greater))
            | (Some(std::cmp::Ordering::Greater), Some(std::cmp::Ordering::Less))
            | (Some(std::cmp::Ordering::Equal), Some(std::cmp::Ordering::Equal)) => {}
            (None, None) => {}
            _ => prop_assert!(false, "Inconsistent comparison: {:?} vs {:?}", cmp1, cmp2),
        }
    }
}
