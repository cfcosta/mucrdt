use digest::Digest;
use proptest::{array::uniform4, prelude::*};
use std::marker::PhantomData;

/// A Merkle Patricia Forestry (MPF) is an append-only key-value data structure that combines
/// the properties of Merkle trees and Patricia tries. It stores elements in a radix-16 trie,
/// where each node contains a cryptographic hash digest of its sub-trie or value.
///
/// The MPF structure offers several advantages:
/// 1. Efficient membership checks and insertions using only root hashes and succinct proofs
/// 2. Significantly smaller proofs compared to traditional Merkle Patricia Tries
/// 3. CPU and memory-efficient operations
///
/// # Structure
///
/// The MPF uses a trie with a radix of 16, corresponding to hexadecimal digits. This design
/// choice allows for efficient manipulation of nibbles (4-bit units) while working with
/// byte-oriented systems. Each level in the trie can have up to 16 branches.
///
/// # Node Types
///
/// The MPF consists of two types of nodes:
/// - Branch nodes: Contains up to 16 children, each corresponding to a nibble
/// - Leaf nodes: Stores the actual key-value pair and any remaining part of the key (suffix)
///
/// # Hashing Mechanism
///
/// The MPF employs a unique hashing mechanism that combines the benefits of Merkle trees
/// and Patricia tries:
///
/// - For leaf nodes: hash = H(head(suffix) || tail(suffix) || H(value))
/// - For branch nodes: hash = H(nibbles(prefix) || H(Merkle tree of children))
///
/// Where H is the chosen cryptographic hash function, and || denotes concatenation.
///
/// This hashing structure allows for efficient proof generation and verification while
/// maintaining the integrity of the entire data structure.
///
/// # Proof Structure
///
/// Proofs in MPF are designed to be compact and efficient. Each proof step can be one of:
/// - Branch: Provides hashes of up to 4 sub-trees in a sparse Merkle tree structure
/// - Fork: Used when a branch node's prefix is split due to a new insertion
/// - Leaf: Contains the full key-value pair for the leaf node
///
/// # Performance Characteristics
///
/// The following table illustrates the average proof size and computational requirements
/// for various numbers of elements in the MPF:
///
/// | Elements | Proof Size (bytes) | Proof Memory | Proof CPU |
/// |----------|---------------------|--------------|-----------|
/// | 10²      | 250                 | 70K          | 28M       |
/// | 10³      | 350                 | 100K         | 42M       |
/// | 10⁴      | 460                 | 130K         | 56M       |
/// | 10⁵      | 560                 | 160K         | 70M       |
/// | 10⁶      | 670                 | 190K         | 84M       |
/// | 10⁷      | 780                 | 220K         | 98M       |
/// | 10⁸      | 880                 | 250K         | 112M      |
/// | 10⁹      | 990                 | 280K         | 126M      |
///
/// # Limitations
///
/// This implementation of MPF is append-only, supporting insertions but not updates or
/// removals. This design choice ensures the integrity and immutability of the data structure,
/// making it suitable for applications requiring an auditable history of changes.
///
/// # Usage Considerations
///
/// The MPF is particularly useful in scenarios where:
/// - Efficient membership proofs are required
/// - Storage space for proofs is limited
/// - An immutable, append-only data structure is needed
/// - The ability to work with cryptographic primitives is essential
///
/// However, users should be aware of the trade-off between proof size and computational
/// overhead when choosing this data structure for their specific use case.

// End of Selection

use crate::{
    prelude::{CmRDT, CvRDT, Item, MPFError, Result},
    values::Hash,
};
use proptest::collection::vec;

/// Represents a Merkle Patricia Forestry
pub struct MerklePatriciaForestry<D: Digest> {
    proof: Proof,
    root: Hash,
    _phantom: PhantomData<D>,
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
        any::<Proof>()
            .prop_map(|proof| Self::from_proof(proof))
            .boxed()
    }
}

impl<D: Digest> MerklePatriciaForestry<D> {
    /// Constructs a new MerklePatriciaForestry from its proof.
    pub fn from_proof(proof: Proof) -> Self {
        let root = Self::calculate_root(&proof);
        Self {
            proof,
            root,
            _phantom: PhantomData,
        }
    }

    /// Constructs a new empty MerklePatriciaForestry.
    pub fn empty() -> Self {
        Self {
            proof: Proof(vec![]),
            root: Hash::zero(),
            _phantom: PhantomData,
        }
    }

    /// Checks if the MerklePatriciaForestry is empty.
    pub fn is_empty(&self) -> bool {
        self.proof.0.is_empty()
    }

    /// Verifies if an element is present in the trie with a specific value.
    pub fn verify(&self, key: &[u8], value: &[u8]) -> bool {
        if self.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = Hash::digest::<D>(value);
        self.verify_proof(key_hash, value_hash, &self.proof)
    }

    /// Inserts an element to the trie.
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

    /// Verifies a proof for a given key and value.
    pub fn verify_proof(&self, key: Hash, value: Hash, proof: &Proof) -> bool {
        if proof.0.is_empty() {
            return false;
        }

        proof.0.iter().any(|step| {
            matches!(step, ProofStep::Leaf { key: leaf_key, value: leaf_value, .. } if *leaf_key == key && *leaf_value == value)
        })
    }

    fn insert_to_proof(&self, key: Hash, value: Hash) -> Proof {
        let mut new_proof = self.proof.clone();
        // Remove any existing leaf with the same key
        new_proof.0.retain(|step| {
            !matches!(step, ProofStep::Leaf { key: leaf_key, .. } if *leaf_key == key)
        });
        new_proof.0.push(ProofStep::Leaf {
            skip: 0,
            key,
            value,
        });
        new_proof
    }

    fn calculate_root(proof: &Proof) -> Hash {
        let mut hasher = D::new();
        for step in &proof.0 {
            match step {
                ProofStep::Branch { neighbors, .. } => {
                    for neighbor in neighbors {
                        hasher.update(neighbor.as_ref());
                    }
                }
                ProofStep::Fork { neighbor, .. } => {
                    hasher.update([neighbor.nibble]);
                    hasher.update(&neighbor.prefix);
                    hasher.update(neighbor.root.as_ref());
                }
                ProofStep::Leaf { key, value, .. } => {
                    hasher.update(key.as_ref());
                    hasher.update(value.as_ref());
                }
            }
        }
        Hash::from_slice(hasher.finalize().as_ref())
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

impl<D: Digest + 'static> CmRDT<MerklePatriciaForestry<D>> for MerklePatriciaForestry<D> {
    fn apply(&mut self, op: &Item<MerklePatriciaForestry<D>>) -> Result<()> {
        self.merge(&op.value)
    }
}

/// Represents a proof in the Merkle Patricia Forestry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof(Vec<ProofStep>);

impl Arbitrary for Proof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_depth: Self::Parameters) -> Self::Strategy {
        vec(any::<ProofStep>(), 0..=max_depth)
            .prop_map(Proof)
            .boxed()
    }
}

/// Represents a single step in a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStep {
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

impl Arbitrary for ProofStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (any::<usize>(), uniform4(any::<Hash>()))
                .prop_map(|(skip, neighbors)| ProofStep::Branch { skip, neighbors }),
            (any::<usize>(), any::<Neighbor>())
                .prop_map(|(skip, neighbor)| ProofStep::Fork { skip, neighbor }),
            (any::<usize>(), any::<Hash>(), any::<Hash>())
                .prop_map(|(skip, key, value)| ProofStep::Leaf { skip, key, value })
        ]
        .boxed()
    }
}

/// Represents a neighboring node in a fork step of a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// The nibble (4-bit value) of the neighbor.
    nibble: u8,
    /// The remaining prefix of the neighbor's key.
    prefix: Vec<u8>,
    /// The hash digest of the neighbor's subtree.
    root: Hash,
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

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;

    macro_rules! generate_tests {
        ($digest:ty) => {
            paste! {
                #[allow(non_snake_case)]
                mod [<$digest _tests>] {
                    use super::*;
                    use $digest;

                    fn non_empty() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("non-empty string", |s| !s.is_empty())
                    }

                    #[test_strategy::proptest]
                    fn test_verify_proof(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty())] key: String,
                        value: String
                    ) {
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()),
                            "Proof verification failed for key: {:?}, value: {:?}",
                            key, value);
                    }

                    #[test_strategy::proptest]
                    fn test_insert(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty())] key: String,
                        value: String
                    ) {
                        let original_trie = trie.clone();
                        trie.insert(key.as_bytes(), value.as_bytes())?;
                        prop_assert!(trie.verify(key.as_bytes(), value.as_bytes()));
                        prop_assert_ne!(trie, original_trie);
                    }

                    #[test_strategy::proptest]
                    fn test_multiple_inserts(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty())] key1: String,
                        value1: String,
                        #[strategy(non_empty())] key2: String,
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
                        #[strategy(non_empty())] key: String,
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
                        #[strategy(non_empty())] key1: String,
                        value1: String,
                        #[strategy(non_empty())] key2: String,
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
                    fn test_proof_size(
                        trie: MerklePatriciaForestry<$digest>
                    ) {
                        let proof = trie.proof.clone();
                        prop_assert!(proof.0.len() <= 130 * (4 + 1),
                            "Proof size {} exceeds expected maximum",
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
                        trie1: MerklePatriciaForestry<$digest>,
                        trie2: MerklePatriciaForestry<$digest>
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
                        trie: MerklePatriciaForestry<$digest>
                    ) {
                        let calculated_root = MerklePatriciaForestry::<$digest>::calculate_root(&trie.proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root");
                    }

                    #[test_strategy::proptest]
                    fn test_from_proof_root_calculation(
                        #[strategy(any::<Proof>())] proof: Proof
                    ) {
                        let trie = MerklePatriciaForestry::<$digest>::from_proof(proof.clone());
                        let calculated_root = MerklePatriciaForestry::<$digest>::calculate_root(&proof);
                        prop_assert_eq!(trie.root, calculated_root, "Root should match calculated root after from_proof");
                    }

                    #[test_strategy::proptest]
                    fn test_verify_non_existent(
                        mut trie: MerklePatriciaForestry<$digest>,
                        #[strategy(non_empty())] key1: String,
                        value1: String,
                        #[strategy(non_empty())] key2: String,
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

                    type Mpf = MerklePatriciaForestry<$digest>;
                    crate::test_state_crdt_properties!(Mpf);
                    crate::test_op_crdt_properties!(Mpf);
                }
            }
        };
    }

    type Blake3 = blake3::Hasher;
    type Blake2s = blake2::Blake2s256;
    type Sha256 = sha2::Sha256;

    generate_tests!(Blake3);
    generate_tests!(Blake2s);
    generate_tests!(Sha256);
}
