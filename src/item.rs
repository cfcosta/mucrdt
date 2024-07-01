use std::cmp::Ordering;

use proptest::prelude::*;

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Item<T> {
    pub id: Identifier,
    pub value: T,
}

impl<T: Eq> PartialOrd for Item<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Eq> Ord for Item<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T: Arbitrary + 'static> Arbitrary for Item<T> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<(Identifier, T)>()
            .prop_map(|(id, value)| Self { id, value })
            .boxed()
    }
}

impl<T> Item<T> {
    pub fn new(id: Identifier, value: T) -> Self {
        Self { id, value }
    }
}
