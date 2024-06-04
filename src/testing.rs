

use itertools::{Itertools};
use proptest::{
    collection::hash_set,
    prelude::{prop::collection::vec, *},
    sample::SizeRange,
    strategy::ValueTree,
    test_runner::{Config as TestConfig, TestRunner},
};

use crate::prelude::*;

pub use proptest::test_runner::TestRng;

/// Generated a sorted collection of timestamps
pub fn timestamps(size: impl Into<SizeRange>) -> impl Strategy<Value = Vec<Timestamp>> {
    hash_set(any::<Timestamp>(), size)
        .prop_map(|timestamps| timestamps.into_iter().sorted().collect_vec())
}

pub fn accounts(size: impl Into<SizeRange>) -> impl Strategy<Value = Vec<Account>> {
    vec(any::<Account>(), size)
}

pub fn rng() -> impl Strategy<Value = TestRng> {
    Just(()).prop_perturb(|_, rng| rng)
}

pub fn unwrap_strategy<T: Arbitrary + Default + Clone>(strategy: impl Strategy<Value = T>) -> T {
    let mut test_runner = TestRunner::new(TestConfig::default());

    strategy
        .new_tree(&mut test_runner)
        .expect("Failed to get new value from strategy")
        .current()
}

/// Shorthand for `any_with::<A>(vec(any::<B>(), size))`.
pub fn v<A, B>(size: impl Into<SizeRange>) -> impl Strategy<Value = A>
where
    A: Arbitrary<Parameters = Vec<B>, Strategy = BoxedStrategy<A>>,
    B: Arbitrary,
{
    vec(any::<B>(), size).prop_flat_map(A::arbitrary_with)
}
