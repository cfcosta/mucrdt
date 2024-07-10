use crate::prelude::*;
use digest::Digest;

mod proof;
mod step;

pub use proof::Proof;
pub use step::{Step, Direction};

pub struct HashGraph<D: Digest> {
    root: Hash,
    proof: Proof,
    _phantom: std::marker::PhantomData<D>,
}

impl<D: Digest> std::fmt::Debug for HashGraph<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashGraph")
            .field("root", &self.root)
            .field("proof", &self.proof)
            .finish()
    }
}

impl<D: Digest> proptest::arbitrary::Arbitrary for HashGraph<D> {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<Hash>(), any::<Proof>())
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
            root: Hash::zero(),
            proof: Proof::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.is_empty() || value.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        self.insert_recursive(key_hash, value_hash, 0);
        self.recalculate_root();
        Ok(())
    }

    fn recalculate_root(&mut self) {
        self.root = self.calculate_root_from_proof(&self.proof);
    }

    fn calculate_root_from_proof(&self, proof: &Proof) -> Hash {
        let mut current_hash = Hash::zero();
        for step in proof.steps().iter().rev() {
            match step {
                Step::Branch { direction, sibling, .. } => {
                    current_hash = match direction {
                        Direction::Left => Hash::combine::<D>(&current_hash, sibling),
                        Direction::Right => Hash::combine::<D>(sibling, &current_hash),
                    };
                }
                Step::Leaf { value, .. } => {
                    current_hash = *value;
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
            self.proof.push(Step::Leaf {
                skip: depth,
                key: key_hash,
                value: value_hash,
            });
            return value_hash;
        }

        let bit = (key_hash.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;

        if let Some(step) = self.proof.get(depth).cloned() {
            match step {
                Step::Branch { skip, sibling, .. } => {
                    let (new_hash, new_sibling) = if bit == 0 {
                        (self.insert_recursive(key_hash, value_hash, depth + 1), sibling)
                    } else {
                        (sibling, self.insert_recursive(key_hash, value_hash, depth + 1))
                    };
                    let new_direction = if bit == 0 { Direction::Left } else { Direction::Right };
                    let combined_hash = Hash::combine::<D>(&new_hash, &new_sibling);
                    self.proof.set(depth, Step::Branch {
                        skip,
                        direction: new_direction,
                        sibling: new_sibling,
                    });
                    combined_hash
                }
                Step::Leaf { skip, key: existing_key, value: existing_value } => {
                    if existing_key == key_hash {
                        self.proof.set(depth, Step::Leaf {
                            skip,
                            key: key_hash,
                            value: value_hash,
                        });
                        value_hash
                    } else {
                        let existing_bit = (existing_key.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;
                        if existing_bit == bit {
                            let new_hash = self.insert_recursive(key_hash, value_hash, depth + 1);
                            let existing_hash = self.insert_recursive(existing_key, existing_value, depth + 1);
                            let (direction, sibling) = if bit == 0 {
                                (Direction::Left, existing_hash)
                            } else {
                                (Direction::Right, new_hash)
                            };
                            let combined_hash = Hash::combine::<D>(&new_hash, &existing_hash);
                            self.proof.set(depth, Step::Branch {
                                skip,
                                direction,
                                sibling,
                            });
                            combined_hash
                        } else {
                            let (direction, sibling) = if bit == 0 {
                                (Direction::Left, existing_value)
                            } else {
                                (Direction::Right, value_hash)
                            };
                            let combined_hash = Hash::combine::<D>(&value_hash, &existing_value);
                            self.proof.set(depth, Step::Branch {
                                skip,
                                direction,
                                sibling,
                            });
                            combined_hash
                        }
                    }
                }
            }
        } else {
            self.proof.push(Step::Leaf {
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
        if let Some(step) = self.proof.get(depth) {
            match step {
                Step::Branch { direction, .. } => {
                    let bit = (key_hash.as_ref()[depth / 8] >> (7 - (depth % 8))) & 1;
                    let expected_direction = if bit == 0 { Direction::Left } else { Direction::Right };
                    if *direction == expected_direction {
                        self.verify_recursive(key_hash, value_hash, depth + 1)
                    } else {
                        false
                    }
                }
                Step::Leaf {
                    key: stored_key,
                    value: stored_value,
                    ..
                } => key_hash == *stored_key && value_hash == *stored_value,
            }
        } else {
            false
        }
    }

    pub fn generate_proof(&self, key: &[u8]) -> Option<Vec<Step>> {
        if key.is_empty() {
            return None;
        }
        let key_hash = Hash::digest::<D>(key);
        self.generate_proof_recursive(key_hash, 0)
    }

    fn generate_proof_recursive(&self, key_hash: Hash, depth: usize) -> Option<Vec<Step>> {
        if let Some(step) = self.proof.get(depth) {
            match step {
                Step::Branch { skip, direction, sibling } => {
                    if let Some(mut proof) = self.generate_proof_recursive(key_hash, depth + 1) {
                        proof.push(Step::Branch {
                            skip: *skip,
                            direction: direction.clone(),
                            sibling: *sibling,
                        });
                        Some(proof)
                    } else {
                        None
                    }
                }
                Step::Leaf {
                    key: stored_key,
                    value,
                    ..
                } => {
                    if stored_key == &key_hash {
                        Some(vec![Step::Leaf {
                            skip: depth,
                            key: *stored_key,
                            value: *value,
                        }])
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    }

    pub fn verify_proof(&self, key: &[u8], value: &[u8], proof: &[Step]) -> bool {
        if key.is_empty() || value.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        let mut current_hash = if let Some(Step::Leaf {
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
                Step::Branch { direction, sibling, .. } => {
                    let bit = (key_hash.as_ref()[(proof.len() - 2) / 8]
                        >> (7 - ((proof.len() - 2) % 8)))
                        & 1;
                    let expected_direction = if bit == 0 { Direction::Left } else { Direction::Right };
                    if *direction != expected_direction {
                        return false;
                    }
                    current_hash = match direction {
                        Direction::Left => Hash::combine::<D>(&current_hash, sibling),
                        Direction::Right => Hash::combine::<D>(sibling, &current_hash),
                    };
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
                        assert!(empty_graph.proof.is_empty());
                        assert_eq!(empty_graph.root, Hash::zero());
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
                        let initial_size = graph.proof.len();
                        graph.insert(&large_key, &large_value).unwrap();
                        prop_assert!(graph.verify(&large_key, &large_value),
                            "Failed to verify large key-value pair");

                        let size_increase = graph.proof.len() - initial_size;
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
                        prop_assert!(proof.len() <= 256,
                            "Proof size {} exceeds expected maximum of 256",
                            proof.len());
                    }

                    #[test]
                    fn test_empty_key() {
                        let mut graph = HashGraph::<$digest>::new();
                        assert!(matches!(graph.insert(&[], b"value"), Err(Error::EmptyKeyOrValue)));
                        assert!(matches!(graph.insert(b"key", &[]), Err(Error::EmptyKeyOrValue)));
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
                        #[strategy(vec(any::<Step>(), 0..10))] malicious_steps: Vec<Step>
                    ) {
                        let mut malicious_proof = graph.proof.clone();
                        malicious_proof.extend(malicious_steps);

                        let malicious_graph = HashGraph::<$digest> {
                            root: Hash::digest::<$digest>(&malicious_proof.iter().flat_map(|s| s.to_bytes()).collect::<Vec<u8>>()),
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