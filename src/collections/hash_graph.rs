use crate::collections::{MerkleProof, MerkleStep, Neighbor};
use crate::{error::MPFError, values::Hash, prelude::*};
use digest::Digest;

pub struct HashGraph<D: Digest> {
    root: Hash,
    proof: MerkleProof,
    _phantom: std::marker::PhantomData<D>,
}

impl<D: Digest> std::fmt::Debug for HashGraph<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashGraph")
            .field("root", &self.root)
            .finish()
    }
}

impl<D: Digest> proptest::arbitrary::Arbitrary for HashGraph<D> {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<Hash>(), any::<MerkleProof>())
            .prop_map(|(root, proof)| HashGraph {
                root,
                proof,
                _phantom: std::marker::PhantomData,
            })
            .boxed()
    }
}

impl<D: Digest> HashGraph<D> {
    pub fn new() -> Self {
        HashGraph {
            root: Hash::default(),
            proof: MerkleProof(Vec::new()),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), MPFError> {
        if key.is_empty() || value.is_empty() {
            return Err(MPFError::EmptyKeyOrValue);
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        self.insert_recursive(key_hash, value_hash, 0);
        self.recalculate_root();
        Ok(())
    }

    fn recalculate_root(&mut self) {
        self.root = self.calculate_root_from_proof(&self.proof.clone());
    }

    fn calculate_root_from_proof(&self, proof: &MerkleProof) -> Hash {
        let mut current_hash = Hash::default();
        for step in proof.0.iter().rev() {
            match step {
                MerkleStep::Branch { neighbors, .. } => {
                    current_hash = Hash::combine::<D>(&neighbors[0], &neighbors[1]);
                }
                MerkleStep::Leaf { value, .. } => {
                    current_hash = *value;
                }
                MerkleStep::Fork { neighbor, .. } => {
                    current_hash = Hash::combine::<D>(&current_hash, &neighbor.root);
                }
            }
        }
        current_hash
    }

    fn compute_value_hash(&self, key: &[u8], value: &[u8]) -> Hash {
        let mut data = Vec::with_capacity(key.len() + 8 + value.len());
        data.extend_from_slice(key);
        data.extend_from_slice(&(value.len() as u64).to_be_bytes());
        data.extend_from_slice(value);
        Hash::digest::<D>(&data)
    }

    fn insert_recursive(&mut self, key_hash: Hash, value_hash: Hash, depth: usize) -> Hash {
        if depth == 256 {
            self.proof.0.push(MerkleStep::Leaf {
                skip: depth,
                key: key_hash,
                value: value_hash,
            });
            return value_hash;
        }

        let bit = (key_hash.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;

        if let Some(step) = self.proof.0.get(depth).cloned() {
            match step {
                MerkleStep::Branch { skip, neighbors } => {
                    let (new_left, new_right) = if bit == 0 {
                        (
                            self.insert_recursive(key_hash, value_hash, depth + 1),
                            neighbors[1],
                        )
                    } else {
                        (
                            neighbors[0],
                            self.insert_recursive(key_hash, value_hash, depth + 1),
                        )
                    };
                    let new_hash = Hash::combine::<D>(&new_left, &new_right);
                    self.proof.0[depth] = MerkleStep::Branch {
                        skip,
                        neighbors: [new_left, new_right, Hash::zero(), Hash::zero()],
                    };
                    new_hash
                }
                MerkleStep::Leaf { skip, key: existing_key, value: existing_value } => {
                    if existing_key == key_hash {
                        self.proof.0[depth] = MerkleStep::Leaf {
                            skip,
                            key: key_hash,
                            value: value_hash,
                        };
                        value_hash
                    } else {
                        let existing_bit = (existing_key.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;
                        if existing_bit == bit {
                            let new_hash = self.insert_recursive(key_hash, value_hash, depth + 1);
                            let existing_hash = self.insert_recursive(existing_key, existing_value, depth + 1);
                            let (left, right) = if bit == 0 {
                                (new_hash, existing_hash)
                            } else {
                                (existing_hash, new_hash)
                            };
                            let combined_hash = Hash::combine::<D>(&left, &right);
                            self.proof.0[depth] = MerkleStep::Branch {
                                skip,
                                neighbors: [left, right, Hash::zero(), Hash::zero()],
                            };
                            combined_hash
                        } else {
                            let (left, right) = if bit == 0 {
                                (value_hash, existing_value)
                            } else {
                                (existing_value, value_hash)
                            };
                            let new_hash = Hash::combine::<D>(&left, &right);
                            self.proof.0[depth] = MerkleStep::Branch {
                                skip,
                                neighbors: [left, right, Hash::zero(), Hash::zero()],
                            };
                            new_hash
                        }
                    }
                }
                MerkleStep::Fork { skip, neighbor } => {
                    let new_neighbor = if bit == 0 {
                        Neighbor {
                            nibble: (key_hash.as_ref()[depth / 2] >> (4 - 4 * (depth % 2))) & 0xF,
                            prefix: key_hash.as_ref()[depth / 2 + 1..].to_vec(),
                            root: self.insert_recursive(key_hash, value_hash, depth + 1),
                        }
                    } else {
                        neighbor.clone()
                    };
                    let new_hash = Hash::combine::<D>(&new_neighbor.root, &neighbor.root);
                    self.proof.0[depth] = MerkleStep::Fork {
                        skip,
                        neighbor: new_neighbor,
                    };
                    new_hash
                }
            }
        } else {
            self.proof.0.push(MerkleStep::Leaf {
                skip: depth,
                key: key_hash,
                value: value_hash,
            });
            value_hash
        }
    }

    pub fn verify(&self, key: &[u8], value: &[u8]) -> bool {
        if key.is_empty() || value.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        self.verify_recursive(key_hash, value_hash, 0)
    }

    fn verify_recursive(&self, key_hash: Hash, value_hash: Hash, depth: usize) -> bool {
        if let Some(step) = self.proof.0.get(depth) {
            match step {
                MerkleStep::Branch { .. } => {
                    let bit = (key_hash.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;
                    if bit == 0 {
                        self.verify_recursive(key_hash, value_hash, depth + 1)
                    } else {
                        self.verify_recursive(key_hash, value_hash, depth + 1)
                    }
                }
                MerkleStep::Leaf {
                    key: stored_key,
                    value: stored_value,
                    ..
                } => key_hash == *stored_key && value_hash == *stored_value,
                MerkleStep::Fork { .. } => {
                    let bit = (key_hash.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;
                    if bit == 0 {
                        self.verify_recursive(key_hash, value_hash, depth + 1)
                    } else {
                        self.verify_recursive(key_hash, value_hash, depth + 1)
                    }
                }
            }
        } else {
            false
        }
    }

    pub fn generate_proof(&self, key: &[u8]) -> Option<Vec<MerkleStep>> {
        if key.is_empty() {
            return None;
        }
        let key_hash = Hash::digest::<D>(key);
        self.generate_proof_recursive(key_hash, 0)
    }

    fn generate_proof_recursive(&self, key_hash: Hash, depth: usize) -> Option<Vec<MerkleStep>> {
        if let Some(step) = self.proof.0.get(depth) {
            match step {
                MerkleStep::Branch { skip, neighbors } => {
                    if let Some(mut proof) = self.generate_proof_recursive(key_hash, depth + 1) {
                        proof.push(MerkleStep::Branch {
                            skip: *skip,
                            neighbors: *neighbors,
                        });
                        Some(proof)
                    } else {
                        None
                    }
                }
                MerkleStep::Leaf {
                    key: stored_key,
                    value,
                    ..
                } => {
                    if stored_key == &key_hash {
                        Some(vec![MerkleStep::Leaf {
                            skip: depth,
                            key: *stored_key,
                            value: *value,
                        }])
                    } else {
                        None
                    }
                }
                MerkleStep::Fork { skip, neighbor } => {
                    if let Some(mut proof) = self.generate_proof_recursive(key_hash, depth + 1) {
                        proof.push(MerkleStep::Fork {
                            skip: *skip,
                            neighbor: neighbor.clone(),
                        });
                        Some(proof)
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    }

    pub fn verify_proof(&self, key: &[u8], value: &[u8], proof: &[MerkleStep]) -> bool {
        if key.is_empty() || value.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        let mut current_hash = if let Some(MerkleStep::Leaf {
            key: proof_key,
            value: proof_value,
            ..
        }) = proof.first()
        {
            if proof_key != &key_hash || proof_value != &value_hash {
                return false;
            }
            *proof_value
        } else {
            return false;
        };

        for step in proof.iter().skip(1) {
            match step {
                MerkleStep::Branch { neighbors, .. } => {
                    let bit = (key_hash.as_ref()[(proof.len() - 2) / 8]
                        >> (7 - ((proof.len() - 2) % 8)))
                        & 1;
                    if bit == 0 {
                        current_hash = Hash::combine::<D>(&current_hash, &neighbors[1]);
                    } else {
                        current_hash = Hash::combine::<D>(&neighbors[0], &current_hash);
                    }
                }
                MerkleStep::Fork { neighbor, .. } => {
                    let bit = (key_hash.as_ref()[(proof.len() - 2) / 8]
                        >> (7 - ((proof.len() - 2) % 8)))
                        & 1;
                    if bit == 0 {
                        current_hash = Hash::combine::<D>(&current_hash, &neighbor.root);
                    } else {
                        current_hash = Hash::combine::<D>(&neighbor.root, &current_hash);
                    }
                }
                _ => return false,
            }
        }

        current_hash == self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    macro_rules! generate_hashgraph_tests {
        ($digest:ty) => {
            paste::paste! {
                #[allow(non_snake_case)]
                mod [<$digest _tests>] {
                    use super::*;
                    use $digest;
                    use proptest::collection::vec;

                    fn non_empty_string() -> impl Strategy<Value = String> {
                        any::<String>().prop_filter("must not be empty", |s| !s.is_empty())
                    }

                    #[test_strategy::proptest]
                    fn test_insert_and_verify(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        #[strategy(non_empty_string())] value: String
                    ) {
                        let original_root = graph.root;
                        graph.insert(key.as_bytes(), value.as_bytes()).unwrap();
                        prop_assert_ne!(graph.root, original_root, "Root should change after insertion");
                        prop_assert!(graph.verify(key.as_bytes(), value.as_bytes()),
                            "Failed to verify inserted key-value pair");
                    }

                    #[test]
                    fn test_empty_graph() {
                        let empty_graph = HashGraph::<$digest>::new();
                        assert!(empty_graph.proof.0.is_empty());
                        assert_eq!(empty_graph.root, Hash::default());
                    }

                    #[test_strategy::proptest]
                    fn test_insert_overwrite(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        #[strategy(non_empty_string())] value1: String,
                        #[strategy(non_empty_string())] value2: String
                    ) {
                        prop_assume!(value1 != value2);

                        graph.insert(key.as_bytes(), value1.as_bytes()).unwrap();
                        let root_after_first_insert = graph.root;

                        graph.insert(key.as_bytes(), value2.as_bytes()).unwrap();
                        prop_assert_ne!(graph.root, root_after_first_insert);
                        prop_assert!(graph.verify(key.as_bytes(), value2.as_bytes()));
                        prop_assert!(!graph.verify(key.as_bytes(), value1.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_large_key_value_pairs(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = graph.proof.0.len();
                        graph.insert(&large_key, &large_value).unwrap();
                        prop_assert!(graph.verify(&large_key, &large_value),
                            "Failed to verify large key-value pair");

                        let size_increase = graph.proof.0.len() - initial_size;
                        prop_assert!(size_increase <= 256,
                            "Graph size increase {} exceeds maximum expected increase of 256",
                            size_increase);
                    }

                    #[test_strategy::proptest]
                    fn test_generate_and_verify_proof(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(non_empty_string())] key: String,
                        #[strategy(non_empty_string())] value: String
                    ) {
                        graph.insert(key.as_bytes(), value.as_bytes()).unwrap();

                        let proof = graph.generate_proof(key.as_bytes());
                        prop_assert!(proof.is_some(), "Failed to generate proof");

                        let proof = proof.unwrap();
                        prop_assert!(graph.verify_proof(key.as_bytes(), value.as_bytes(), &proof),
                            "Failed to verify generated proof");

                        // Use a non-empty incorrect value
                        prop_assert!(!graph.verify_proof(key.as_bytes(), b"incorrect_value", &proof),
                            "Incorrectly verified proof with wrong value");

                        // Use a non-empty incorrect key
                        prop_assert!(!graph.verify_proof(b"incorrect_key", value.as_bytes(), &proof),
                            "Incorrectly verified proof with wrong key");
                    }

                    #[test_strategy::proptest]
                    fn test_verify_non_existent(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(non_empty_string())] key1: String,
                        #[strategy(non_empty_string())] value1: String,
                        #[strategy(non_empty_string())] key2: String,
                        #[strategy(non_empty_string())] value2: String
                    ) {
                        prop_assume!(key1 != key2);
                        prop_assume!(value1 != value2);

                        graph.insert(key1.as_bytes(), value1.as_bytes()).unwrap();

                        prop_assert!(graph.verify(key1.as_bytes(), value1.as_bytes()));
                        prop_assert!(!graph.verify(key2.as_bytes(), value1.as_bytes()));
                        prop_assert!(!graph.verify(key1.as_bytes(), value2.as_bytes()));
                        prop_assert!(!graph.verify(key2.as_bytes(), value2.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_proof_size(
                        #[strategy(any::<HashGraph<$digest>>())] graph: HashGraph<$digest>
                    ) {
                        let proof = graph.proof.clone();
                        prop_assert!(proof.0.len() <= 256,
                            "Proof size {} exceeds expected maximum of 256",
                            proof.0.len());
                    }

                    #[test]
                    fn test_empty_key() {
                        let mut graph = HashGraph::<$digest>::new();
                        assert!(matches!(graph.insert(&[], b"value"), Err(MPFError::EmptyKeyOrValue)));
                        assert!(matches!(graph.insert(b"key", &[]), Err(MPFError::EmptyKeyOrValue)));
                    }

                    #[test_strategy::proptest]
                    fn test_root_proof_equality(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph1: HashGraph<$digest>,
                        #[strategy(any::<HashGraph<$digest>>())] mut graph2: HashGraph<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key: Vec<u8>,
                        value: u8
                    ) {
                        graph1.insert(&key, &[value]).unwrap();
                        graph2.insert(&key, &[value]).unwrap();

                        prop_assert_eq!(graph1.root, graph2.root, "Roots should be equal after inserting the same key-value pair");
                        prop_assert_eq!(graph1.proof, graph2.proof, "Proofs should be equal after inserting the same key-value pair");
                    }

                    #[test_strategy::proptest]
                    fn test_malicious_proof_resistance(
                        #[strategy(any::<HashGraph<$digest>>())] graph: HashGraph<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key: Vec<u8>,
                        value: u8,
                        #[strategy(vec(any::<MerkleStep>(), 0..10))] malicious_steps: Vec<MerkleStep>
                    ) {
                        let mut malicious_proof = graph.proof.clone();
                        malicious_proof.0.extend(malicious_steps);

                        let malicious_graph = HashGraph::<$digest> {
                            root: Hash::digest::<$digest>(&malicious_proof.0.iter().flat_map(|s| s.to_bytes()).collect::<Vec<u8>>()),
                            proof: malicious_proof,
                            _phantom: std::marker::PhantomData,
                        };

                        prop_assert!(!malicious_graph.verify(&key, &[value]), "Malicious proof falsely verified");
                        prop_assert_ne!(graph.root, malicious_graph.root, "Malicious graph has the same root hash");
                    }
                }
            }
        };
    }

    type Blake3 = blake3::Hasher;
    type Blake2s = blake2::Blake2s256;
    type Sha256 = sha2::Sha256;

    generate_hashgraph_tests!(Blake3);
    generate_hashgraph_tests!(Blake2s);
    generate_hashgraph_tests!(Sha256);
}