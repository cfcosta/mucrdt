use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

use super::Step;
use proptest::{collection::vec, prelude::*};

use crate::prelude::*;

/// Represents a proof in the HashGraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof(Vec<Step>);

impl Proof {
    /// Creates a new, empty `Proof`.
    ///
    /// This method is equivalent to calling `Proof::default()`.
    ///
    /// # Returns
    ///
    /// A new `Proof` instance with no steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::Proof;
    ///
    /// let proof = Proof::new();
    /// assert!(proof.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the steps in the proof.
    ///
    /// # Returns
    ///
    /// A slice containing all the steps in the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let proof = Proof::new();
    /// let steps: &[Step] = proof.steps();
    /// ```
    pub fn steps(&self) -> &[Step] {
        &self.0
    }

    /// Returns the root hash of the proof.
    ///
    /// # Returns
    ///
    /// - If the proof is empty, returns the default hash.
    /// - Otherwise, returns the hash of the last step in the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Hash};
    ///
    /// let proof = Proof::new();
    /// let root_hash: Hash = proof.root();
    /// ```
    pub fn root(&self) -> Hash {
        if self.is_empty() {
            return Hash::default();
        }

        match self.last().unwrap() {
            Step::Branch { neighbors, .. } => neighbors[0],
            Step::Fork { neighbor, .. } => neighbor.root,
            Step::Leaf { value, .. } => *value,
        }
    }

    /// Returns a reference to the step at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the step to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the `Step` at the given index, or `None` if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let proof = Proof::new();
    /// let step: Option<&Step> = proof.get(0);
    /// ```
    pub fn get(&self, index: usize) -> Option<&Step> {
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
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let mut proof = Proof::new();
    /// proof.retain(|step| match step {
    ///     Step::Leaf { .. } => true,
    ///     _ => false,
    /// });
    /// ```
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Step) -> bool,
    {
        self.0.retain(f);
    }

    /// Removes and returns the step at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the step to remove.
    ///
    /// # Returns
    ///
    /// The removed `Step` if the index is in bounds, or `None` if it is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let mut proof = Proof::new();
    /// let removed_step: Option<Step> = proof.remove(0);
    /// ```
    pub fn remove(&mut self, index: usize) -> Option<Step> {
        if index < self.0.len() {
            Some(self.0.remove(index))
        } else {
            None
        }
    }

    /// Appends a step to the end of the proof.
    ///
    /// # Arguments
    ///
    /// * `step` - The `Step` to append to the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Step::Leaf { key: vec![], value: Hash::default() });
    /// ```
    pub fn push(&mut self, step: Step) {
        self.0.push(step);
    }

    /// Extends the proof with the contents of an iterator.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator that yields `Step`s to be appended to the proof.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let mut proof = Proof::new();
    /// let steps = vec![Step::Leaf { key: vec![], value: Hash::default() }];
    /// proof.extend(steps);
    /// ```
    pub fn extend<I: IntoIterator<Item = Step>>(&mut self, iter: I) {
        self.0.extend(iter);
    }

    /// Sets the step at the specified index to a new value.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the step to set.
    /// * `step` - The new `Step` to set at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use mucrdt::forestry::{Proof, Step};
    ///
    /// let mut proof = Proof::new();
    /// proof.push(Step::Leaf { key: vec![], value: Hash::default() });
    /// proof.set(0, Step::Leaf { key: vec![1], value: Hash::default() });
    /// ```
    pub fn set(&mut self, index: usize, step: Step) {
        self.0[index] = step;
    }
}

impl Deref for Proof {
    type Target = [Step];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Proof {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Step>> for Proof {
    fn from(steps: Vec<Step>) -> Self {
        Proof(steps)
    }
}

impl From<Proof> for Vec<Step> {
    fn from(proof: Proof) -> Self {
        proof.0
    }
}

impl IntoIterator for Proof {
    type Item = Step;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Proof {
    type Item = &'a Step;
    type IntoIter = std::slice::Iter<'a, Step>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Proof {
    type Item = &'a mut Step;
    type IntoIter = std::slice::IterMut<'a, Step>;

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

        // If lengths are equal, compare each step
        for (self_step, other_step) in self.iter().zip(other.iter()) {
            match self_step.partial_cmp(other_step) {
                Some(Ordering::Equal) => continue,
                ord => return ord,
            }
        }

        // If all steps are equal, the proofs are equal
        Some(Ordering::Equal)
    }
}

impl Arbitrary for Proof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_depth: Self::Parameters) -> Self::Strategy {
        vec(any::<Step>(), 0..=max_depth).prop_map(Proof).boxed()
    }
}

impl Default for Proof {
    fn default() -> Self {
        Proof(Vec::new())
    }
}