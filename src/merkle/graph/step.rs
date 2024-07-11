use crate::prelude::*;
use core::cmp::Ordering;
use digest::Digest;
use proptest::prelude::*;

/// Represents a single step in a proof for a HashGraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A branch node in the graph.
    Branch {
        /// The number of bits to skip in the key.
        skip: usize,
        /// The hash digests of the two parent branches.
        left: Hash,
        right: Hash,
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
            Step::Branch { skip, left, right } => {
                let mut bytes = vec![0u8; 1 + 8 + 32 + 32];
                bytes[0] = 0; // Indicator for Branch
                bytes[1..9].copy_from_slice(&skip.to_be_bytes());
                bytes[9..41].copy_from_slice(left.as_ref());
                bytes[41..73].copy_from_slice(right.as_ref());
                bytes
            }
            Step::Leaf { skip, key, value } => {
                let mut bytes = vec![0u8; 1 + 8 + 32 + 32];
                bytes[0] = 1; // Indicator for Leaf
                bytes[1..9].copy_from_slice(&skip.to_be_bytes());
                bytes[9..41].copy_from_slice(key.as_ref());
                bytes[41..73].copy_from_slice(value.as_ref());
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
                if bytes.len() != 1 + std::mem::size_of::<usize>() + 64 {
                    return Err(Error::Deserialization(
                        "Invalid length for Branch".to_string(),
                    ));
                }
                let skip = usize::from_le_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .map_err(|_| Error::Deserialization("Failed to convert skip bytes".to_string()))?
                );
                let left = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>()..1 + std::mem::size_of::<usize>() + 32],
                );
                let right = Hash::from_slice(
                    &bytes[1 + std::mem::size_of::<usize>() + 32..],
                );
                Ok(Step::Branch { skip, left, right })
            }
            1 => {
                // Leaf
                if bytes.len() != 1 + std::mem::size_of::<usize>() + 64 {
                    return Err(Error::Deserialization(
                        "Invalid length for Leaf".to_string(),
                    ));
                }
                let skip = usize::from_le_bytes(
                    bytes[1..1 + std::mem::size_of::<usize>()]
                        .try_into()
                        .map_err(|_| Error::Deserialization("Failed to convert skip bytes".to_string()))?
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
        let branch_strategy = (
            any::<usize>(),
            any::<Hash>(),
            any::<Hash>(),
        )
            .prop_map(|(skip, left, right)| Step::Branch { skip, left, right });

        let leaf_strategy = (any::<usize>(), any::<Hash>(), any::<Hash>())
            .prop_map(|(skip, key, value)| Step::Leaf { skip, key, value });

        prop_oneof![branch_strategy, leaf_strategy].boxed()
    }
}

impl PartialOrd for Step {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                Step::Branch { skip: s1, left: l1, right: r1 },
                Step::Branch { skip: s2, left: l2, right: r2 },
            ) => s1
                .partial_cmp(s2)
                .and_then(|o| {
                    if o == Ordering::Equal {
                        l1.partial_cmp(l2)
                    } else {
                        Some(o)
                    }
                })
                .and_then(|o| {
                    if o == Ordering::Equal {
                        r1.partial_cmp(r2)
                    } else {
                        Some(o)
                    }
                }),
            (
                Step::Leaf { skip: s1, key: k1, value: v1 },
                Step::Leaf { skip: s2, key: k2, value: v2 },
            ) => s1
                .partial_cmp(s2)
                .and_then(|o| {
                    if o == Ordering::Equal {
                        k1.partial_cmp(k2)
                    } else {
                        Some(o)
                    }
                })
                .and_then(|o| {
                    if o == Ordering::Equal {
                        v1.partial_cmp(v2)
                    } else {
                        Some(o)
                    }
                }),
            (Step::Branch { .. }, Step::Leaf { .. }) => Some(Ordering::Less),
            (Step::Leaf { .. }, Step::Branch { .. }) => Some(Ordering::Greater),
        }
    }
}

impl Step {
    pub fn hash<D: Digest>(&self) -> Hash {
        match self {
            Step::Branch { skip, left, right } => {
                let mut hasher = D::new();
                hasher.update(&skip.to_be_bytes());
                hasher.update(left.as_ref());
                hasher.update(right.as_ref());
                Hash::from_slice(hasher.finalize().as_ref())
            }
            Step::Leaf { skip, key, value } => {
                let mut hasher = D::new();
                hasher.update(&skip.to_be_bytes());
                hasher.update(key.as_ref());
                hasher.update(value.as_ref());
                Hash::from_slice(hasher.finalize().as_ref())
            }
        }
    }

    pub fn verify<D: Digest>(
        &self,
        target_key: &Hash,
        proof_path: &[Step],
    ) -> Result<Option<Hash>> {
        let mut current_hash = self.hash::<D>();
        let mut current_key = target_key.clone();

        for step in proof_path.iter() {
            match step {
                Step::Branch { skip, left, right } => {
                    if !Self::verify_skip(&current_key, *skip) {
                        return Err(Error::InvalidProof("Invalid skip in branch".to_string()));
                    }

                    let mut hasher = D::new();
                    hasher.update(&skip.to_be_bytes());
                    hasher.update(left.as_ref());
                    hasher.update(right.as_ref());

                    current_hash = Hash::from_slice(hasher.finalize().as_ref());

                    if current_hash != self.hash::<D>() {
                        return Err(Error::InvalidProof("Invalid hash in branch".to_string()));
                    }

                    current_key = Self::update_key(&current_key, *skip);
                }
                Step::Leaf { skip, key, value } => {
                    if !Self::verify_skip(&current_key, *skip) {
                        return Err(Error::InvalidProof("Invalid skip in leaf".to_string()));
                    }

                    if key != &current_key {
                        return Err(Error::InvalidProof("Key mismatch in leaf".to_string()));
                    }

                    let leaf_hash = {
                        let mut hasher = D::new();
                        hasher.update(&skip.to_be_bytes());
                        hasher.update(key.as_ref());
                        hasher.update(value.as_ref());
                        Hash::from_slice(hasher.finalize().as_ref())
                    };

                    if leaf_hash != current_hash {
                        return Err(Error::InvalidProof("Invalid hash in leaf".to_string()));
                    }

                    return Ok(Some(*value));
                }
            }
        }

        Err(Error::InvalidProof(
            "Proof does not end with a leaf".to_string(),
        ))
    }

    pub fn verify_skip(key: &Hash, skip: usize) -> bool {
        // Verify that the first 'skip' bits of the key are zero
        let bytes_to_check = skip / 8;
        let bits_to_check = skip % 8;

        // Check full bytes
        if bytes_to_check > 0 && key.as_ref()[..bytes_to_check] != vec![0; bytes_to_check] {
            return false;
        }

        // Check remaining bits
        if bits_to_check > 0 {
            if bytes_to_check >= key.as_ref().len() {
                return false;
            }
            let mask = 0xFF << (8 - bits_to_check);
            if key.as_ref()[bytes_to_check] & mask != 0 {
                return false;
            }
        }

        true
    }

    pub fn update_key(key: &Hash, skip: usize) -> Hash {
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