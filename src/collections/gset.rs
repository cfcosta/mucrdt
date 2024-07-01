use std::{collections::BTreeSet, hash::Hash};

use proptest::{collection::btree_set, prelude::*};

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GSet<T: Clone + Hash> {
    pub values: BTreeSet<T>,
}

impl<T: Clone + Hash> Default for GSet<T> {
    fn default() -> Self {
        Self {
            values: BTreeSet::new(),
        }
    }
}

impl<T> CvRDT for GSet<T>
where
    T: Arbitrary + Clone + Hash + PartialEq + Eq + Ord + 'static,
{
    fn merge(&mut self, other: &Self) -> Result<()> {
        let v = self.values.clone();

        for value in other.values.difference(&v) {
            self.values.insert(value.clone());
        }

        Ok(())
    }
}

impl<T> CmRDT<T> for GSet<T>
where
    T: Arbitrary + Clone + Hash + PartialEq + Eq + Ord + 'static,
{
    fn apply(&mut self, other: &T) -> Result<()> {
        if !self.values.contains(other) {
            self.values.insert(other.clone());
        }

        Ok(())
    }
}

impl<T> Arbitrary for GSet<T>
where
    T: Arbitrary + Clone + Hash + PartialEq + Eq + Ord + 'static,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        btree_set(any::<T>(), 0..10)
            .prop_map(|values| Self { values })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    pub type GSet = super::GSet<u64>;
    pub type Num = u64;

    crate::prelude::test_state_crdt_properties!(GSet);
    crate::prelude::test_op_crdt_properties!(GSet, Num);
}
