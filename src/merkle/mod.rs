pub mod forestry;
pub mod graph;

use crate::prelude::*;
use proptest::prelude::*;

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