use crate::prelude::*;
use digest::Digest;

mod proof;
pub use proof::Proof;

#[derive(Clone)]
pub struct HashGraph<D: Digest> {
    root: Hash,
    nodes: Vec<Node>,
    _phantom: std::marker::PhantomData<D>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    hash: Hash,
    left_parent: Option<usize>,
    right_parent: Option<usize>,
}

impl proptest::arbitrary::Arbitrary for Node {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (
            any::<Hash>(),
            proptest::option::of(any::<usize>()),
            proptest::option::of(any::<usize>()),
        )
            .prop_map(|(hash, left_parent, right_parent)| Node {
                hash,
                left_parent,
                right_parent,
            })
            .boxed()
    }
}


impl<D: Digest> std::fmt::Debug for HashGraph<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashGraph")
            .field("root", &self.root)
            .field("nodes", &self.nodes)
            .finish()
    }
}

impl<D: Digest> proptest::arbitrary::Arbitrary for HashGraph<D> {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<Hash>(), any::<Vec<Node>>())
            .prop_map(|(root, nodes)| HashGraph {
                root,
                nodes,
                _phantom: std::marker::PhantomData,
            })
            .boxed()
    }
}

impl<D: Digest> HashGraph<D> {
    pub fn new() -> Self {
        HashGraph {
            root: Hash::zero(),
            nodes: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn nodes(&self) -> &Vec<Node> {
        &self.nodes
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.is_empty() || value.is_empty() {
            return Err(Error::EmptyKeyOrValue);
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        let new_node_index = self.nodes.len();
        self.nodes.push(Node {
            hash: value_hash,
            left_parent: None,
            right_parent: None,
        });
        self.update_parents(new_node_index, key_hash);
        self.recalculate_root();
        Ok(())
    }

    fn recalculate_root(&mut self) {
        if let Some(last_node) = self.nodes.last() {
            self.root = last_node.hash;
        }
    }

    fn compute_value_hash(&self, key: &[u8], value: &[u8]) -> Hash {
        let mut data = Vec::with_capacity(key.len() + 8 + value.len());
        data.extend_from_slice(key);
        data.extend_from_slice(&(value.len() as u64).to_be_bytes());
        data.extend_from_slice(value);
        Hash::digest::<D>(&data)
    }

    fn update_parents(&mut self, node_index: usize, key_hash: Hash) {
        let mut left_parent = None;
        let mut right_parent = None;

        for (i, node) in self.nodes.iter().enumerate().rev() {
            if node.hash == key_hash {
                if left_parent.is_none() {
                    left_parent = Some(i);
                } else if right_parent.is_none() {
                    right_parent = Some(i);
                    break;
                }
            }
        }

        if let Some(node) = self.nodes.get_mut(node_index) {
            node.left_parent = left_parent;
            node.right_parent = right_parent;
        }
    }

    pub fn verify(&self, key: &[u8], value: &[u8]) -> bool {
        if key.is_empty() || value.is_empty() {
            return false;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        self.nodes.iter().any(|node| node.hash == value_hash && self.verify_parents(node, key_hash))
    }

    fn verify_parents(&self, node: &Node, key_hash: Hash) -> bool {
        match (node.left_parent, node.right_parent) {
            (Some(left_index), Some(right_index)) => {
                let left_node = &self.nodes[left_index];
                let right_node = &self.nodes[right_index];
                left_node.hash == key_hash && right_node.hash == key_hash
            }
            _ => false,
        }
    }

    pub fn generate_proof(&self, key: &[u8], value: &[u8]) -> Option<Proof> {
        if key.is_empty() || value.is_empty() {
            return None;
        }
        let key_hash = Hash::digest::<D>(key);
        let value_hash = self.compute_value_hash(key, value);
        let mut proof = Proof::new();

        for node in &self.nodes {
            if node.hash == value_hash && self.verify_parents(node, key_hash) {
                proof.push(node.hash);
                return Some(proof);
            }
        }
        None
    }
}

#[cfg(all(test, any(feature = "blake3", feature = "blake2", feature = "sha2")))]
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
                        let original_root = *graph.root();
                        graph.insert(key.as_bytes(), value.as_bytes()).unwrap();
                        prop_assert_ne!(*graph.root(), original_root, "Root should change after insertion");
                        prop_assert!(graph.verify(key.as_bytes(), value.as_bytes()),
                            "Failed to verify inserted key-value pair");
                    }

                    #[test]
                    fn test_empty_graph() {
                        let empty_graph = HashGraph::<$digest>::new();
                        assert!(empty_graph.nodes().is_empty());
                        assert_eq!(*empty_graph.root(), Hash::zero());
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
                        let root_after_first_insert = *graph.root();

                        graph.insert(key.as_bytes(), value2.as_bytes()).unwrap();
                        prop_assert_ne!(*graph.root(), root_after_first_insert);
                        prop_assert!(graph.verify(key.as_bytes(), value2.as_bytes()));
                        prop_assert!(!graph.verify(key.as_bytes(), value1.as_bytes()));
                    }

                    #[test_strategy::proptest]
                    fn test_large_key_value_pairs(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph: HashGraph<$digest>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_key: Vec<u8>,
                        #[strategy(vec(any::<u8>(), 100..1000))] large_value: Vec<u8>
                    ) {
                        let initial_size = graph.nodes().len();
                        graph.insert(&large_key, &large_value).unwrap();
                        prop_assert!(graph.verify(&large_key, &large_value),
                            "Failed to verify large key-value pair");

                        let size_increase = graph.nodes().len() - initial_size;
                        prop_assert!(size_increase <= 256,
                            "Graph size increase {} exceeds maximum expected increase of 256",
                            size_increase);
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

                    #[test]
                    fn test_empty_key() {
                        let mut graph = HashGraph::<$digest>::new();
                        assert!(matches!(graph.insert(&[], b"value"), Err(Error::EmptyKeyOrValue)));
                        assert!(matches!(graph.insert(b"key", &[]), Err(Error::EmptyKeyOrValue)));
                    }

                    #[test_strategy::proptest]
                    fn test_root_nodes_equality(
                        #[strategy(any::<HashGraph<$digest>>())] mut graph1: HashGraph<$digest>,
                        #[strategy(any::<HashGraph<$digest>>())] mut graph2: HashGraph<$digest>,
                        #[strategy(vec(any::<u8>(), 1..100))] key: Vec<u8>,
                        value: u8
                    ) {
                        graph1.insert(&key, &[value]).unwrap();
                        graph2.insert(&key, &[value]).unwrap();

                        prop_assert_eq!(graph1.root, graph2.root, "Roots should be equal after inserting the same key-value pair");
                        prop_assert_eq!(graph1.nodes, graph2.nodes, "Nodes should be equal after inserting the same key-value pair");
                    }
                }
            }
        };
    }

    #[cfg(feature = "blake3")]
    type Blake3 = blake3::Hasher;
    #[cfg(feature = "blake2")]
    type Blake2s = blake2::Blake2s256;
    #[cfg(feature = "sha2")]
    type Sha256 = sha2::Sha256;

    #[cfg(feature = "blake3")]
    generate_hashgraph_tests!(Blake3);
    #[cfg(feature = "blake2")]
    generate_hashgraph_tests!(Blake2s);
    #[cfg(feature = "sha2")]
    generate_hashgraph_tests!(Sha256);
}
