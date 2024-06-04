use std::{cmp::Ordering, hash::Hash};

use proptest::{collection::vec, prelude::*};

use crate::prelude::*;

#[derive(Debug, Clone)]
pub enum Register<T> {
    Single(VClock, Vec<T>),
    Multi(VClock, Vec<T>),
}

impl<T> Default for Register<T>
where
    T: Clone + Hash + Default,
{
    fn default() -> Self {
        Self::Single(Default::default(), Default::default())
    }
}

impl<T: Clone + Hash> Register<T> {
    pub fn new(author: Pubkey, value: T) -> Self {
        let mut clock = VClock::new();
        clock.inc(author);

        Self::Single(clock, vec![value])
    }

    pub fn clock(&self) -> &VClock {
        match self {
            Self::Single(clock, _) => clock,
            Self::Multi(clock, _) => clock,
        }
    }

    pub fn clock_mut(&mut self) -> &mut VClock {
        match self {
            Self::Single(clock, _) => clock,
            Self::Multi(clock, _) => clock,
        }
    }

    pub fn read(&self) -> Vec<T> {
        match self {
            Self::Single(_, data) => data.clone(),
            Self::Multi(_, data) => data.clone(),
        }
    }

    pub fn update(&mut self, actor: Pubkey, value: &T) {
        let mut clock = self.clock().clone();
        clock.inc(actor);
        *self = Self::Single(clock, vec![value.clone()]);
    }
}

impl<T> PartialEq for Register<T>
where
    T: Clone + Hash,
{
    fn eq(&self, other: &Self) -> bool {
        self.clock() == other.clock()
    }
}

impl<T> Eq for Register<T> where T: Clone + Hash {}

impl<T> PartialOrd for Register<T>
where
    T: Clone + Hash,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.clock().partial_cmp(other.clock())
    }
}

impl<T> Hash for Register<T>
where
    T: Clone + Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.clock().to_bytes().hash(state);
    }
}

impl<T> Arbitrary for Register<T>
where
    T: 'static + Arbitrary,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<VClock>(), vec(any::<T>(), 1..10))
            .prop_map(|(clock, data)| match data.len() {
                1 => Self::Single(clock, data),
                _ => Self::Multi(clock, data),
            })
            .boxed()
    }
}

impl<T> CvRDT for Register<T>
where
    T: 'static + Arbitrary + Clone + Hash + Default,
{
    fn merge(&mut self, other: &Self) -> Result<()> {
        let id = self.clock_mut();

        match (*id).partial_cmp(other.clock()) {
            Some(Ordering::Greater) => {
                id.merge(other.clock())?;
                *self = Self::Single(id.clone(), self.read())
            }
            _ => {
                id.merge(other.clock())?;
                *self = Self::Multi(id.clone(), [self.read(), other.read()].concat());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use proptest::prelude::*;
    use rand::seq::IteratorRandom;
    use test_strategy::proptest;

    use crate::prelude::*;

    type Register = super::Register<u64>;
    crate::test_state_crdt_properties!(Register);

    #[proptest(fork = false)]
    fn test_clock_mut_is_same_as_clock(mut a: Register, b: Register) {
        prop_assert_eq!(a == b, a.clock_mut() == b.clock());
    }

    #[proptest(fork = false)]
    fn test_arbitrary_always_is_single_if_theres_just_one_element(a: Register) {
        prop_assert!(!a.read().is_empty());

        prop_assert_eq!(matches!(a, Register::Single(_, _)), a.read().len() == 1);
        prop_assert_eq!(matches!(a, Register::Multi(_, _)), a.read().len() > 1);
    }

    #[proptest(fork = false)]
    fn test_equality_if_clocks_are_the_same(a: Register, b: Register) {
        prop_assert_eq!(a == b, a.clock() == b.clock());
    }

    #[proptest(fork = false)]
    fn test_ordering_is_possible_if_clocks_are_convergent(
        #[strategy(rng())] mut rng: TestRng,
        a: Register,
    ) {
        let mut b = a.clone();
        b.clock_mut()
            .inc(a.clock().actors().choose(&mut rng).unwrap());

        prop_assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        prop_assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));
    }

    #[proptest(fork = false)]
    fn test_ordering_is_impossible_if_clocks_diverge(a: Register, b: Register) {
        prop_assume!(a.clock().diverges(b.clock()));
        prop_assert_eq!(a.partial_cmp(&b), None);
    }

    #[proptest(fork = false)]
    fn test_multiple_values_on_concurrent_merges(
        mut clock: VClock,
        original: u64,
        val_a: u64,
        val_b: u64,
        acc_a: Pubkey,
        acc_b: Pubkey,
    ) {
        prop_assume!(original != val_a && val_a != val_b);

        let mut a = Register::Single(clock.clone(), vec![original]);
        let mut b = Register::Single(clock.clone(), vec![original]);

        a.update(acc_a, &val_a);
        b.update(acc_b, &val_b);

        a.merge(&b)?;

        clock.inc(acc_a);
        clock.inc(acc_b);

        prop_assert_eq!(a, Register::Multi(clock, vec![val_a, val_b]));
    }

    #[proptest(fork = false)]
    fn test_concurrent_merges_get_replaced_by_later_events(
        #[strategy(rng())] mut rng: TestRng,
        old: (u64, u64),
        new: u64,
        mut a: Register,
        mut b: Register,
    ) {
        prop_assume!(a != b);
        prop_assume!(a.clock().diverges(b.clock()));

        let acc_a = a.clock().actors().choose(&mut rng).unwrap();
        let acc_b = a.clock().actors().choose(&mut rng).unwrap();

        a.update(acc_a, &old.0);
        b.update(acc_b, &old.1);

        a.merge(&b)?;

        let mut clock = a.clock().clone();
        clock.inc(acc_a);

        let c = Register::Single(clock, vec![new]);
        a.merge(&c)?;

        prop_assert_eq!(a, c);
    }
}
