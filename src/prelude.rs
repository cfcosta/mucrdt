use proptest::prelude::*;

pub use crate::{
    merkle::*, error::*, hash::*,
};

pub trait CvRDT: Sized + Arbitrary + Default + Clone + PartialEq {
    fn merge(&mut self, other: &Self) -> Result<()>;
}

pub trait CmRDT<T>: Sized + Arbitrary + Default + Clone + PartialEq {
    fn apply(&mut self, other: &T) -> Result<()>;
}

pub trait FromBytes
where
    Self: Sized,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

pub trait ToBytes {
    type Output: AsRef<[u8]>;

    /// Converts the value to a representation in bytes.
    fn to_bytes(&self) -> Self::Output;

    /// Converts the value to a representation in bytes, as a vector.
    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    fn to_bytes_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    /// Hashes the value using the blake3 algorithm.
    ///
    /// This is a convenience method, and automatically derived from `to_bytes`.
    fn hash_bytes(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.to_bytes().as_ref());
        hasher.finalize()
    }

    /// Checks if the value (as bytes) is zero.
    ///
    /// This is useful for checking if a value is empty.
    fn is_zero(&self) -> bool {
        let len = self.to_bytes().as_ref().len();
        self.to_bytes_vec() == vec![0; len]
    }
}

pub trait FromHex
where
    Self: Sized,
{
    fn from_hex(hex: &str) -> Result<Self>;
}

pub trait ToHex {
    fn to_hex(&self) -> String;
}
