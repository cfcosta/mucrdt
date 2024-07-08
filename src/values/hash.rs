use std::fmt::{Display, Formatter};

use digest::Digest;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;

use crate::error::Result;

/// Custom Hash type containing the inner field
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Arbitrary for Hash {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<[u8; 32]>().prop_map(Hash::new).boxed()
    }
}

impl Hash {
    /// Creates a new Hash from any type that can be converted into [u8; 32].
    pub fn new<T: Into<[u8; 32]>>(data: T) -> Self {
        Hash(data.into())
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut inner = [0u8; 32];
        inner.copy_from_slice(slice);
        Hash(inner)
    }

    /// Returns a zero hash (all bytes set to 0).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Creates a new Hash from a hexadecimal string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;

        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength)?;
        }

        Ok(Self::from_slice(&bytes))
    }

    pub fn digest<D: Digest>(data: &[u8]) -> Self {
        let mut hasher = D::new();
        hasher.update(data);
        Hash::from_slice(&hasher.finalize())
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::zero()
    }
}

impl From<[u8; 32]> for Hash {
    fn from(array: [u8; 32]) -> Self {
        Hash(array)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Hash> for [u8; 32] {
    fn from(val: Hash) -> Self {
        val.0
    }
}
