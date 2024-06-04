use std::{collections::HashSet, hash::Hash};

use proptest::{collection::hash_set, prelude::*};

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GSet<T: Clone + Hash> {
    pub values: HashSet<Register<T>>,
}

impl<T: Clone + Hash> Default for GSet<T> {
    fn default() -> Self {
        Self {
            values: HashSet::new(),
        }
    }
}

impl<T: Arbitrary + Clone + Hash + PartialEq + 'static> CvRDT for GSet<T> {
    fn merge(&mut self, other: &Self) -> Result<()> {
        self.values.extend(other.values.clone());

        Ok(())
    }
}

impl<T: Arbitrary + Clone + Hash + PartialEq + 'static> Arbitrary for GSet<T> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        hash_set(any::<Register<T>>(), 0..10)
            .prop_map(|values| Self { values })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    pub type GSet = super::GSet<u64>;
    crate::prelude::test_state_crdt_properties!(GSet);
}
