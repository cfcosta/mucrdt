use core::cmp::Ordering;
use proptest::prelude::*;
use crate::prelude::*;
use digest::Digest;

/// Represents the direction taken at a branch node
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl PartialOrd for Direction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Direction::Left, Direction::Left) => Some(Ordering::Equal),
            (Direction::Right, Direction::Right) => Some(Ordering::Equal),
            (Direction::Left, Direction::Right) => Some(Ordering::Less),
            (Direction::Right, Direction::Left) => Some(Ordering::Greater),
        }
    }
}

/// Represents a single step in a proof for a HashGraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A branch node in the graph.
    Branch {
        /// The number of bits to skip in the key.
        skip: usize,
        /// The direction taken at this branch.
        direction: Direction,
        /// The hash digest of the sibling branch.
        sibling: Hash,
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
            Step::Branch { skip, direction, sibling } => {
                let mut bytes = vec![0u8]; // 0 indicates Branch
                bytes.extend_from_slice(&skip.to_be_bytes());
                bytes.push(match direction {
                    Direction::Left => 0,
                    Direction::Right => 1,
                });
                bytes.extend_from_slice(sibling.as_ref());
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
            return Err(Error::Deserialization("Empty input".to_string()));
        }

        match bytes[0] {
            0 => {
                // Branch
                if bytes.len() < 1 + std::mem::size_of::<usize>() + 1 + 32 {
                    return Err(Error::Deserialization(
                        "Invalid length for Branch".to_string(),
                    ));
                }
                let skip = usize::from_be_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap(),
                );
                let direction = match bytes[1 + std::mem::size_of::<usize>()] {
                    0 => Direction::Left,
                    1 => Direction::Right,
                    _ => return Err(Error::Deserialization("Invalid direction".to_string())),
                };
                let sibling = Hash::from_slice(&bytes[1 + std::mem::size_of::<usize>() + 1..]);
                Ok(Step::Branch { skip, direction, sibling })
            }
            1 => {
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
            _ => Err(Error::Deserialization(
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
            prop_oneof![Just(Direction::Left), Just(Direction::Right)],
            any::<Hash>(),
        )
            .prop_map(|(skip, direction, sibling)| Step::Branch { skip, direction, sibling });

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
                    direction: d1,
                    sibling: sib1,
                },
                Step::Branch {
                    skip: s2,
                    direction: d2,
                    sibling: sib2,
                },
            ) => s1.partial_cmp(s2)
                .and_then(|o| if o == Ordering::Equal { d1.partial_cmp(d2) } else { Some(o) })
                .and_then(|o| if o == Ordering::Equal { sib1.partial_cmp(sib2) } else { Some(o) }),
            (
                Step::Leaf { skip: s1, key: k1, value: v1 },
                Step::Leaf { skip: s2, key: k2, value: v2 },
            ) => s1.partial_cmp(s2)
                .and_then(|o| if o == Ordering::Equal { k1.partial_cmp(k2) } else { Some(o) })
                .and_then(|o| if o == Ordering::Equal { v1.partial_cmp(v2) } else { Some(o) }),
            (Step::Branch { .. }, Step::Leaf { .. }) => Some(Ordering::Less),
            (Step::Leaf { .. }, Step::Branch { .. }) => Some(Ordering::Greater),
        }
    }
}
impl Step {
    pub fn hash<D: Digest>(&self) -> Hash {
        match self {
            Step::Branch { skip, direction, sibling } => {
                // Compute hash based on skip, direction, and sibling
                // This is where the implicit merging happens
                let mut hasher = D::new();
                hasher.update(&skip.to_be_bytes());
                hasher.update(&[match direction {
                    Direction::Left => 0,
                    Direction::Right => 1,
                }]);
                hasher.update(sibling.as_ref());
                Hash::from_slice(hasher.finalize().as_ref())
            }
            Step::Leaf { skip, key, value } => {
                // Compute hash of leaf data
                let mut hasher = D::new();
                hasher.update(&skip.to_be_bytes());
                hasher.update(key.as_ref());
                hasher.update(value.as_ref());
                Hash::from_slice(hasher.finalize().as_ref())
            }
        }
    }

    pub fn verify<D: Digest>(&self, target_key: &Hash, proof_path: &[Step]) -> Result<Option<Hash>> {
        let mut current_hash = self.hash::<D>();
        let mut current_key = target_key.clone();

        for step in proof_path.iter() {
            match step {
                Step::Branch { skip, direction, sibling } => {
                    // Verify the skip bits
                    if !Self::verify_skip(&current_key, *skip) {
                        return Err(Error::InvalidProof("Invalid skip in branch".to_string()));
                    }

                    // Compute the hash of the current node
                    let mut hasher = D::new();
                    hasher.update(&skip.to_be_bytes());
                    hasher.update(&[match direction {
                        Direction::Left => 0,
                        Direction::Right => 1,
                    }]);
                    hasher.update(sibling.as_ref());

                    // Combine the current hash with the sibling hash
                    current_hash = match direction {
                        Direction::Left => Hash::combine::<D>(&current_hash, sibling),
                        Direction::Right => Hash::combine::<D>(sibling, &current_hash),
                    };

                    // Verify that the computed hash matches the expected hash
                    if current_hash != Hash::from_slice(hasher.finalize().as_ref()) {
                        return Err(Error::InvalidProof("Invalid hash in branch".to_string()));
                    }

                    // Update the current key
                    current_key = Self::update_key(&current_key, *skip);
                }
                Step::Leaf { skip, key, value } => {
                    // Verify the skip bits
                    if !Self::verify_skip(&current_key, *skip) {
                        return Err(Error::InvalidProof("Invalid skip in leaf".to_string()));
                    }

                    // Verify that the key matches the target key
                    if key != &current_key {
                        return Err(Error::InvalidProof("Key mismatch in leaf".to_string()));
                    }

                    // Compute the hash of the leaf
                    let leaf_hash = {
                        let mut hasher = D::new();
                        hasher.update(&skip.to_be_bytes());
                        hasher.update(key.as_ref());
                        hasher.update(value.as_ref());
                        Hash::from_slice(hasher.finalize().as_ref())
                    };

                    // Verify that the computed hash matches the current hash
                    if leaf_hash != current_hash {
                        return Err(Error::InvalidProof("Invalid hash in leaf".to_string()));
                    }

                    // Return the value if all verifications pass
                    return Ok(Some(*value));
                }
            }
        }

        // If we've gone through all steps without finding a leaf, the proof is invalid
        Err(Error::InvalidProof("Proof does not end with a leaf".to_string()))
    }

    fn verify_skip(key: &Hash, skip: usize) -> bool {
        // Verify that the first 'skip' bits of the key are zero
        let bytes_to_check = skip / 8;
        let bits_to_check = skip % 8;

        // Check full bytes
        if key.as_ref()[..bytes_to_check] != vec![0; bytes_to_check] {
            return false;
        }

        // Check remaining bits
        if bits_to_check > 0 {
            let mask = 0xFF << (8 - bits_to_check);
            if key.as_ref()[bytes_to_check] & mask != 0 {
                return false;
            }
        }

        true
    }

    fn update_key(key: &Hash, skip: usize) -> Hash {
        let mut new_key = *key;
        let bytes_to_clear = skip / 8;
        let bits_to_clear = skip % 8;

        // Clear full bytes
        for byte in new_key.as_mut()[..bytes_to_clear].iter_mut() {
            *byte = 0;
        }

        // Clear remaining bits
        if bits_to_clear > 0 {
            let mask = !(0xFF << (8 - bits_to_clear));
            new_key.as_mut()[bytes_to_clear] &= mask;
        }

        new_key
    }
}