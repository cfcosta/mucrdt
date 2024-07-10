use core::cmp::Ordering;
use proptest::prelude::*;
use crate::prelude::*;

/// Represents a single step in a proof for a HashGraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A branch node in the graph.
    Branch {
        /// The number of bits to skip in the key.
        skip: usize,
        /// The hash digests of the neighboring branches.
        neighbors: Vec<Hash>,
    },
    /// A leaf node in the graph.
    Leaf {
        /// The number of bits to skip in the key.
        skip: usize,
        /// The full key of the leaf.
        key: Hash,
        /// The value stored at the leaf.
        value: Hash,
    },
}

impl ToBytes for Step {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        match self {
            Step::Branch { skip, neighbors } => {
                let mut bytes = vec![0u8]; // 0 indicates Branch
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend_from_slice(&(neighbors.len() as u32).to_be_bytes());
                for neighbor in neighbors {
                    bytes.extend_from_slice(neighbor.as_ref());
                }
                bytes
            }
            Step::Leaf { skip, key, value } => {
                let mut bytes = vec![1u8]; // 1 indicates Leaf
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend_from_slice(key.as_ref());
                bytes.extend_from_slice(value.as_ref());
                bytes
            }
        }
    }
}

impl FromBytes for Step {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::FailedDeserialization("Empty input".to_string()));
        }

        match bytes[0] {
            0 => {
                // Branch
                if bytes.len() < 1 + std::mem::size_of::<usize>() + std::mem::size_of::<u32>() {
                    return Err(Error::FailedDeserialization(
                        "Invalid length for Branch".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let num_neighbors = u32::from_be_bytes(
                    bytes[1 + std::mem::size_of::<usize>()..1 + std::mem::size_of::<usize>() + 4]
                        .try_into()
                        .unwrap(),
                );
                let mut neighbors = Vec::with_capacity(num_neighbors as usize);
                for i in 0..num_neighbors {
                    let start = 1 + std::mem::size_of::<usize>() + 4 + (i as usize) * 32;
                    neighbors.push(Hash::from_slice(&bytes[start..start + 32]));
                }
                Ok(Step::Branch { skip, neighbors })
            }
            1 => {
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
                Ok(Step::Leaf { skip, key, value })
            }
            _ => Err(Error::FailedDeserialization(
                "Invalid Step type".to_string(),
            )),
        }
    }
}

impl Arbitrary for Step {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let branch_strategy = (
            any::<usize>(),
            proptest::collection::vec(any::<Hash>(), 1..10),
        )
            .prop_map(|(skip, neighbors)| Step::Branch { skip, neighbors });

        let leaf_strategy = (any::<usize>(), any::<Hash>(), any::<Hash>())
            .prop_map(|(skip, key, value)| Step::Leaf { skip, key, value });

        prop_oneof![branch_strategy, leaf_strategy].boxed()
    }
}

impl PartialOrd for Step {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                Step::Branch {
                    skip: s1,
                    neighbors: n1,
                },
                Step::Branch {
                    skip: s2,
                    neighbors: n2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(Ordering::Equal) => n1.partial_cmp(n2),
                ord => ord,
            },
            (
                Step::Leaf {
                    skip: s1,
                    key: k1,
                    value: v1,
                },
                Step::Leaf {
                    skip: s2,
                    key: k2,
                    value: v2,
                },
            ) => match s1.partial_cmp(s2) {
                Some(Ordering::Equal) => match k1.partial_cmp(k2) {
                    Some(Ordering::Equal) => v1.partial_cmp(v2),
                    ord => ord,
                },
                ord => ord,
            },
            // Define an arbitrary order between different Step variants
            (Step::Branch { .. }, Step::Leaf { .. }) => Some(Ordering::Less),
            (Step::Leaf { .. }, Step::Branch { .. }) => Some(Ordering::Greater),
        }
    }
}
