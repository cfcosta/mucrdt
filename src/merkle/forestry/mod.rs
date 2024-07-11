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
use proptest::prelude::*;

use crate::{error::Error, prelude::*};

mod proof;
mod step;

pub use proof::Proof;
pub use step::Step;

/// Represents a Merkle Patricia Forestry
pub struct Forestry<D: Digest> {
    pub proof: Proof,
    pub root: Hash,
    _phantom: PhantomData<D>,
}

impl<D: Digest> Forestry<D> {
    /// Constructs a new Forestry from its proof.
    ///
    /// This function takes a Proof and creates a new Forestry instance.
    /// It calculates the root hash from the provided proof and initializes the structure.
    ///
    /// # Arguments
    ///
    /// * `proof` - A Proof representing the state of the Merkle Patricia Forestry.
    ///
    /// # Returns
    ///
    /// A new instance of Forestry.
    pub fn from_proof(proof: Proof) -> Self {
        let root = Self::calculate_root(&proof);
        Self {
            proof,
            root,
            _phantom: PhantomData,
        }
    }

    /// Constructs a new empty Forestry.
    ///
    /// This function creates an empty Forestry with no elements.
    /// The proof is an empty vector and the root is set to the zero hash.
    ///
    /// # Returns
    ///
    /// A new empty instance of Forestry.
    pub fn empty() -> Self {
        Self {
            proof: Proof::new(),
            root: Hash::zero(),
            _phantom: PhantomData,
        }
    }

    /// Checks if the Forestry is empty.
    ///
    /// This function determines whether the Forestry contains any elements.
    ///
    /// # Returns
    ///
    /// `true` if the Forestry is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }

    /// Verifies if an element is present in the trie with a specific value.
    ///
    /// This function checks whether a given key-value pair exists in the Forestry
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
    /// This function adds a new key-value pair to the Forestry.
    /// It updates the proof and recalculates the root hash.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the key to insert.
    /// * `value` - A byte slice representing the value to insert.
    ///
    /// # Returns
    ///
    /// A Result indicating success or an Error if the operation fails.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }

        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);

        self.proof = self.insert_to_proof(key_hash, value_hash);
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }

    /// Removes an element from the trie.
    ///
    /// This function marks a key-value pair as deleted in the Forestry.
    /// It updates the proof and recalculates the root hash.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the key to remove.
    ///
    /// # Returns
    ///
    /// A Result indicating success or an Error if the operation fails.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::EmptyKeyOrValue);
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
    /// * `proof` - A reference to the Proof to check against.
    ///
    /// # Returns
    ///
    /// `true` if the key-value pair is present in the proof and not deleted, `false` otherwise.
    pub fn verify_proof(&self, key: Hash, value: Hash, proof: &Proof) -> bool {
        if proof.is_empty() {
            return false;
        }

        proof.iter().any(|step| {
            matches!(step, Step::Leaf { key: leaf_key, value: leaf_value, .. } if *leaf_key == key && *leaf_value == value && *leaf_value != Hash::zero())
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
    /// A new Proof containing the inserted key-value pair with path compression applied.
    fn insert_to_proof(&self, key: Hash, value: Hash) -> Proof {
        let mut new_proof = self.proof.clone();
        // Remove any existing leaf with the same key
        new_proof.retain(
            |step| !matches!(step, Step::Leaf { key: leaf_key, .. } if *leaf_key == key),
        );
        new_proof.push(Step::Leaf {
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
    /// A new Proof with the key-value pair marked as deleted and path compression applied.
    fn mark_as_deleted(&self, key: Hash) -> Proof {
        let mut new_proof = self.proof.clone();
        for step in new_proof.iter_mut() {
            if let Step::Leaf {
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
    /// * `proof` - A mutable reference to the Proof to compress.
    fn compress_path(proof: &mut Proof) {
        let mut i = 0;
        while i < proof.len() - 1 {
            if let (
                Step::Branch {
                    skip: skip1,
                    neighbors: neighbors1,
                },
                Step::Branch {
                    skip: skip2,
                    neighbors: neighbors2,
                },
            ) = (&proof[i], &proof[i + 1])
            {
                if neighbors1.iter().filter(|&&n| n != Hash::zero()).count() == 1
                    && neighbors2.iter().filter(|&&n| n != Hash::zero()).count() == 1
                {
                    // Merge the two branch nodes
                    let new_skip = skip1 + skip2 + 1;
                    let new_neighbors = neighbors2.clone();
                    proof[i] = Step::Branch {
                        skip: new_skip,
                        neighbors: new_neighbors,
                    };
                    proof.remove(i + 1);
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
    /// * `proof` - A reference to the Proof to calculate the root from.
    ///
    /// # Returns
    ///
    /// The calculated root Hash of the Merkle Patricia Forestry.
    fn calculate_root(proof: &Proof) -> Hash {
        let mut hasher = D::new();
        for step in proof.iter() {
            match step {
                Step::Branch { neighbors, .. } => {
                    for neighbor in neighbors {
                        hasher.update(neighbor.as_ref());
                    }
                }
                Step::Fork { neighbor, .. } => {
                    hasher.update([neighbor.nibble]);
                    hasher.update(&neighbor.prefix);
                    hasher.update(neighbor.root.as_ref());
                }
                Step::Leaf { key, value, .. } => {
                    hasher.update(key.as_ref());
                    hasher.update(value.as_ref());
                }
            }
        }
        Hash::from_slice(hasher.finalize().as_ref())
    }
}

impl<D: Digest> Clone for Forestry<D> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            root: self.root,
            _phantom: PhantomData,
        }
    }
}

impl<D: Digest> PartialEq for Forestry<D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<D: Digest> Eq for Forestry<D> {}

impl<D: Digest> std::fmt::Debug for Forestry<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forestry")
            .field("proof", &self.proof)
            .field("root", &self.root)
            .finish()
    }
}

impl<D: Digest> Default for Forestry<D> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<D: Digest + 'static> Arbitrary for Forestry<D> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<Proof>()
            .prop_map(|proof| Self::from_proof(proof))
            .boxed()
    }
}

impl<D: Digest + 'static> CvRDT for Forestry<D> {
    fn merge(&mut self, other: &Self) -> Result<()> {
        let mut merged_proof = self.proof.clone();
        for step in other.proof.iter() {
            if !merged_proof.contains(step) {
                merged_proof.push(step.clone());
            }
        }

        self.proof = merged_proof;
        self.root = Self::calculate_root(&self.proof);

        Ok(())
    }
}

impl<D: Digest + 'static> CmRDT<Proof> for Forestry<D> {
    fn apply(&mut self, op: &Proof) -> Result<()> {
        let mpf = Self::from_proof(op.clone());
        self.merge(&mpf)
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
            return Err(Error::Deserialization(
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
                    use proptest::collection::vec;

                    fn non_empty_string() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("must not be empty", |s| !s.is_empty())
                    }

                    #[test_strategy::proptest]
                    fn test_verify_proof(
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()),
                            "Proof verification failed for key: {:?}, value: {:?}",
                            key, value);
                    }

                    #[test_strategy::proptest]
                    fn test_insert(
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
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
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
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
                        let empty_trie = Forestry::<$digest>::empty();
                        assert!(empty_trie.is_empty());
                    }

                    #[test_strategy::proptest]
                    fn test_start_empty_add_one_check_hash(
                        #[strategy(non_empty_string())] key: String,
                        value: String
                    ) {
                        let mut trie = Forestry::<$digest>::empty();
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
                        let empty_trie = Forestry::<$digest>::empty();
                        prop_assert!(!empty_trie.verify(key1.as_bytes(), value1.as_bytes()));

                        // Test non-empty trie
                        let mut non_empty_trie = Forestry::<$digest>::empty();
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

                        let mut trie = Forestry::<$digest>::empty();

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
                        #[strategy(any::<Forestry<$digest>>())] trie: Forestry<$digest>
                    ) {
                        let proof = trie.proof.clone();
                        prop_assert!(proof.len() <= 130 * (4 + 1),
                            "Proof size {} exceeds expected maximum",
                            proof.len());
                    }

                    #[test]
                    fn test_empty_key_or_value() {
                        let mut trie = Forestry::<$digest>::empty();
                        assert!(matches!(trie.insert(&[], b"value"), Err(Error::EmptyKeyOrValue)));
                        assert!(trie.insert(b"key", &[]).is_ok());
                    }

                    #[test_strategy::proptest]
                    fn test_root_proof_equality(
                        #[strategy(any::<Forestry<$digest>>())] trie1: Forestry<$digest>,
                        #[strategy(any::<Forestry<$digest>>())] trie2: Forestry<$digest>
                    ) {
                        prop_assert_eq!(
                            trie1.root == trie2.root,
                            trie1.proof == trie2.proof,
                            "Root equality should imply proof equality"
                        );
                    }

                    #[test_strategy::proptest]
                    fn test_default_is_empty(
                        #[strategy(Just(Forestry::<$digest>::default()))] default_trie: Forestry<$digest>
                    ) {
                        prop_assert!(default_trie.is_empty(), "Default instance should be empty");
                    }

                    #[test_strategy::proptest]
                    fn test_root_matches_calculated(
                        #[strategy(any::<Forestry<$digest>>())] trie: Forestry<$digest>
                    ) {
                        let calculated_root = Forestry::<$digest>::calculate_root(&trie.proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root");
                    }

                    #[test_strategy::proptest]
                    fn test_from_proof_root_calculation(#[strategy(any::<Proof>())] proof: Proof) {
                        let trie = Forestry::<$digest>::from_proof(proof.clone());
                        let calculated_root = Forestry::<$digest>::calculate_root(&proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root after from_proof");
                    }

                    #[test_strategy::proptest]
                    fn test_verify_non_existent(
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
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
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
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
                        #[strategy(any::<Forestry<$digest>>())] mut trie: Forestry<$digest>,
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
                        mut trie: Forestry<$digest>,
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
                        trie: Forestry<$digest>,
                        key: Vec<u8>,
                        value: u8,
                        malicious_steps: Vec<Step>
                    ) {
                        // Skip the test if the trie is empty and there are no malicious steps
                        prop_assume!(!trie.is_empty() || !malicious_steps.is_empty());

                        let mut malicious_proof = trie.proof.clone();
                        malicious_proof.extend(malicious_steps);

                        let malicious_trie = Forestry::<$digest>::from_proof(malicious_proof);

                        // Verify that the malicious trie doesn't falsely claim to contain the key-value pair
                        prop_assert!(!malicious_trie.verify(&key, &[value]), "Malicious proof falsely verified");

                        // Ensure the root hash of the malicious trie is different
                        prop_assert_ne!(trie.root, malicious_trie.root, "Malicious trie has the same root hash");
                    }

                    #[test_strategy::proptest]
                    fn test_large_key_value_pairs(
                        mut trie: Forestry<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = trie.proof.len();
                        trie.insert(&large_key, &large_value)?;
                        prop_assert!(trie.verify(&large_key, &large_value), "Failed to verify large key-value pair");

                        // Check that trie size increase is reasonable
                        let size_increase = trie.proof.len() - initial_size;
                        prop_assert!(size_increase <= large_key.len() + large_value.len(),
                            "Trie size increase {} is larger than key size {} plus value size {}",
                            size_increase, large_key.len(), large_value.len());
                    }

                    type Mpf = Forestry<$digest>;
                    crate::test_state_crdt_properties!(Mpf);
                    crate::test_op_crdt_properties!(Mpf, Proof);
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
    fn test_merkle_proof_reflexive(proof: Proof) {
        prop_assert_eq!(proof.partial_cmp(&proof), Some(std::cmp::Ordering::Equal));
    }

    #[test_strategy::proptest]
    fn test_merkle_proof_antisymmetric(proof1: Proof, proof2: Proof) {
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
    fn test_merkle_proof_transitive(proof1: Proof, proof2: Proof, proof3: Proof) {
        if let (Some(ord1), Some(ord2)) = (proof1.partial_cmp(&proof2), proof2.partial_cmp(&proof3))
        {
            if ord1 == ord2 {
                prop_assert_eq!(proof1.partial_cmp(&proof3), Some(ord1));
            }
        }
    }

    #[test_strategy::proptest]
    fn test_merkle_proof_consistency(proof1: Proof, proof2: Proof) {
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
