use core::cmp::Ordering;

use proptest::{array::uniform4, prelude::*};

use crate::prelude::*;

/// Represents a single step in a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
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

impl ToBytes for Step {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        match self {
            Step::Branch { skip, neighbors } => {
                let mut bytes = vec![0u8]; // 0 indicates Branch
                bytes.extend_from_slice(&skip.to_be_bytes());
                for neighbor in neighbors {
                    bytes.extend_from_slice(neighbor.as_ref());
                }
                bytes
            }
            Step::Fork { skip, neighbor } => {
                let mut bytes = vec![1u8]; // 1 indicates Fork
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.extend(neighbor.to_bytes());
                bytes
            }
            Step::Leaf { skip, key, value } => {
                let mut bytes = vec![2u8]; // 2 indicates Leaf
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
            return Err(Error::Deserialization("Empty input".to_string()));
        }

        match bytes[0] {
            0 => {
                // Branch
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 4 * 32 {
                    return Err(Error::Deserialization(
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
                Ok(Step::Branch { skip, neighbors })
            }
            1 => {
                // Fork
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 33 {
                    return Err(Error::Deserialization(
                        "Invalid length for Fork".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let neighbor = Neighbor::from_bytes(&bytes[1 + std::mem::size_of::<usize>()..])?;
                Ok(Step::Fork { skip, neighbor })
            }
            2 => {
                // Leaf
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 64 {
                    return Err(Error::Deserialization(
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
            _ => Err(Error::Deserialization("Invalid Step type".to_string())),
        }
    }
}

impl Arbitrary for Step {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (any::<usize>(), uniform4(any::<Hash>()))
                .prop_map(|(skip, neighbors)| Step::Branch { skip, neighbors }),
            (any::<usize>(), any::<Neighbor>())
                .prop_map(|(skip, neighbor)| Step::Fork { skip, neighbor }),
            (any::<usize>(), any::<Hash>(), any::<Hash>())
                .prop_map(|(skip, key, value)| Step::Leaf { skip, key, value })
        ]
        .boxed()
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
                Step::Fork {
                    skip: s1,
                    neighbor: n1,
                },
                Step::Fork {
                    skip: s2,
                    neighbor: n2,
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
            (Step::Branch { .. }, _) => Some(Ordering::Less),
            (_, Step::Branch { .. }) => Some(Ordering::Greater),
            (Step::Fork { .. }, Step::Leaf { .. }) => Some(Ordering::Less),
            (Step::Leaf { .. }, Step::Fork { .. }) => Some(Ordering::Greater),
        }
    }
}
