use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

use digest::Digest;
use proptest::{collection::vec, prelude::*};

use crate::prelude::*;

/// Represents a proof in the HashGraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof(Vec<Hash>);

impl Proof {
    /// Creates a new, empty `Proof`.
    ///
    /// This method is equivalent to calling `Proof::default()`.
    ///
    /// # Returns
    ///
    /// A new `Proof` instance with no hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let proof = Proof::new();
    /// assert!(proof.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the hashes in the proof.
    ///
    /// # Returns
    ///
    /// A slice containing all the hashes in the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let proof = Proof::new();
    /// let hashes: &[Hash] = proof.hashes();
    /// assert!(hashes.is_empty());
    /// ```
    pub fn hashes(&self) -> &[Hash] {
        &self.0
    }

    /// Returns the root hash of the proof.
    ///
    /// The root hash is computed based on the last hash in the proof. If the proof is empty, a default hash is returned.
    ///
    /// # Type Parameters
    ///
    /// * `D` - A type that implements the `Digest` trait.
    ///
    /// # Returns
    ///
    /// The root hash of the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    /// use sha2::Sha256;
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Hash::default());
    /// let root_hash = proof.root::<Sha256>();
    /// ```
    pub fn root<D: Digest>(&self) -> Hash {
        // If the proof is empty, return the default hash
        if self.is_empty() {
            return Hash::default();
        }

        // Otherwise, return the last hash
        *self.last().unwrap()
    }

    /// Returns a reference to the hash at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the hash to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the `Hash` at the given index, or `None` if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let proof = Proof::new();
    /// let hash: Option<&Hash> = proof.get(0);
    /// assert!(hash.is_none());
    /// ```
    pub fn get(&self, index: usize) -> Option<&Hash> {
        self.0.get(index)
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// # Arguments
    ///
    /// * `f` - The predicate function that returns `true` for elements to retain and `false` for elements to remove.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Hash::default());
    /// proof.retain(|hash| !hash.is_zero());
    /// assert!(proof.hashes().is_empty());
    /// ```
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Hash) -> bool,
    {
        self.0.retain(f);
    }

    /// Removes and returns the hash at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the hash to remove.
    ///
    /// # Returns
    ///
    /// The removed `Hash` if the index is in bounds, or `None` if it is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Hash::default());
    /// let removed_hash: Option<Hash> = proof.remove(0);
    /// assert!(removed_hash.is_some());
    /// assert!(proof.is_empty());
    /// ```
    pub fn remove(&mut self, index: usize) -> Option<Hash> {
        if index < self.0.len() {
            Some(self.0.remove(index))
        } else {
            None
        }
    }

    /// Appends a hash to the end of the proof.
    ///
    /// # Arguments
    ///
    /// * `hash` - The `Hash` to append to the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Hash::default());
    /// assert_eq!(proof.hashes().len(), 1);
    /// ```
    pub fn push(&mut self, hash: Hash) {
        self.0.push(hash);
    }

    /// Extends the proof with the contents of an iterator.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator that yields `Hash`es to be appended to the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let mut proof = Proof::new();
    /// let hashes = vec![Hash::default()];
    /// proof.extend(hashes);
    /// assert_eq!(proof.hashes().len(), 1);
    /// ```
    pub fn extend<I: IntoIterator<Item = Hash>>(&mut self, iter: I) {
        self.0.extend(iter);
    }

    /// Sets the hash at the specified index to a new value.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the hash to set.
    /// * `hash` - The new `Hash` to set at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::graph::Proof;
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Hash::default());
    /// proof.set(0, Hash::default());
    /// ```
    pub fn set(&mut self, index: usize, hash: Hash) {
        self.0[index] = hash;
    }
}

impl Deref for Proof {
    type Target = [Hash];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Proof {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Hash>> for Proof {
    fn from(hashes: Vec<Hash>) -> Self {
        Proof(hashes)
    }
}

impl From<Proof> for Vec<Hash> {
    fn from(proof: Proof) -> Self {
        proof.0
    }
}

impl IntoIterator for Proof {
    type Item = Hash;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Proof {
    type Item = &'a Hash;
    type IntoIter = std::slice::Iter<'a, Hash>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Proof {
    type Item = &'a mut Hash;
    type IntoIter = std::slice::IterMut<'a, Hash>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl PartialOrd for Proof {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Compare the lengths of the proof vectors first
        match self.len().partial_cmp(&other.len()) {
            Some(Ordering::Equal) => {}
            ord => return ord,
        }

        // If lengths are equal, compare each hash
        for (self_hash, other_hash) in self.iter().zip(other.iter()) {
            match self_hash.partial_cmp(other_hash) {
                Some(Ordering::Equal) => continue,
                ord => return ord,
            }
        }

        // If all hashes are equal, the proofs are equal
        Some(Ordering::Equal)
    }
}

impl Arbitrary for Proof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_depth: Self::Parameters) -> Self::Strategy {
        vec(any::<Hash>(), 0..=max_depth).prop_map(Proof).boxed()
    }
}

impl Default for Proof {
    fn default() -> Self {
        Proof(Vec::new())
    }
}

impl FromBytes for Proof {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut proof = Proof::default();
        let mut cursor = 0;

        while cursor < bytes.len() {
            let hash = Hash::from_bytes(&bytes[cursor..])?;
            cursor += hash.to_bytes().len();
            proof.0.push(hash);
        }

        Ok(proof)
    }
}

impl ToBytes for Proof {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        let mut bytes = Vec::new();
        for hash in &self.0 {
            bytes.extend_from_slice(&hash.to_bytes());
        }
        bytes
    }
}
