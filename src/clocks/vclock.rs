use std::{cmp::Ordering, collections::BTreeMap};

use itertools::Itertools;
use proptest::{collection::vec, prelude::*};

use crate::prelude::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VClock {
    dots: BTreeMap<Pubkey, u64>,
}

impl_associate_bytes_types!(VClock);

impl VClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn actors(&self) -> impl Iterator<Item = Pubkey> + '_ {
        self.dots.keys().copied()
    }

    pub fn len(&self) -> usize {
        self.dots.keys().count()
    }

    pub fn is_empty(&self) -> bool {
        !self.dots.iter().any(|(_, c)| *c > 0)
    }

    pub fn get(&self, actor: Pubkey) -> u64 {
        self.dots.get(&actor).cloned().unwrap_or(0)
    }

    pub fn diverges(&self, other: &Self) -> bool {
        self.partial_cmp(other).is_none()
    }

    pub fn inc(&mut self, actor: Pubkey) {
        *self.dots.entry(actor).or_insert(0) += 1;
    }
}

impl PartialOrd for VClock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if other.dots.iter().all(|(w, c)| self.get(*w) >= *c) {
            Some(Ordering::Greater)
        } else if self.dots.iter().all(|(w, c)| other.get(*w) >= *c) {
            Some(Ordering::Less)
        } else {
            None
        }
    }
}

impl FromBytes for VClock {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            dots: bytes
                .chunks_exact(32 + 8)
                .map(|chunk| {
                    let actor = Pubkey::from_bytes(chunk[..32].try_into().unwrap())?;
                    let count = u64::from_be_bytes(chunk[32..].try_into().unwrap());

                    Ok::<_, Error>((actor, count))
                })
                .try_collect()?,
        })
    }
}

impl ToBytes for VClock {
    type Output = Vec<u8>;

    fn to_bytes(&self) -> Self::Output {
        self.dots
            .iter()
            .flat_map(|(actor, count)| {
                [actor.to_bytes().to_vec(), count.to_be_bytes().to_vec()].concat()
            })
            .collect()
    }
}

impl CvRDT for VClock {
    fn merge(&mut self, other: &Self) -> Result<()> {
        for (actor, clock) in other.dots.iter() {
            if let Some(c) = self.dots.get_mut(actor) {
                if *clock > *c {
                    *c = *clock;
                }
            } else {
                self.dots.insert(*actor, *clock);
            }
        }
        Ok(())
    }
}

impl Arbitrary for VClock {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        vec(((1..u16::MAX).prop_map(u64::from), any::<Account>()), 3..10)
            .prop_map(|items| {
                items
                    .into_iter()
                    .fold(Self::default(), |mut acc, (count, account)| {
                        acc.dots.insert(account.pubkey(), count);
                        acc
                    })
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{cmp::Ordering, collections::HashSet};

    use proptest::{collection::hash_set, prelude::*};
    use rand::seq::IteratorRandom;
    use test_strategy::proptest;

    use crate::{prelude::*, prop_assert_does_not_change};

    test_state_crdt_properties!(VClock);
    test_to_bytes!(VClock);

    #[proptest(fork = false)]
    fn test_equality_if_clocks_are_the_same(a: VClock, b: VClock) {
        prop_assert_eq!(a == b, a.partial_cmp(&b) == Some(Ordering::Equal));
    }

    #[proptest(fork = false)]
    fn test_equality_commutativity(key_a: Pubkey, key_b: Pubkey) {
        let mut a = VClock::default();
        let mut b = VClock::default();

        a.inc(key_a);
        a.inc(key_b);
        b.inc(key_b);
        b.inc(key_a);

        prop_assert_eq!(a, b);
    }

    #[test]
    fn is_empty_if_there_are_no_dots() {
        let clock = VClock::default();
        assert!(clock.is_empty());
    }

    #[proptest(fork = false)]
    fn test_is_empty_if_all_counters_are_zero(mut clock: VClock) {
        prop_assume!(!clock.is_empty());

        prop_assert_changes!(
            {
                for (_, clock) in clock.dots.iter_mut() {
                    *clock = 0;
                }
            },
            clock.is_empty()
        );
    }

    #[proptest(fork = false)]
    fn test_len_changes_when_adding_new_actors(
        #[strategy(hash_set(any::<Pubkey>(), 0..10))] actors: HashSet<Pubkey>,
    ) {
        let mut clock = VClock::default();

        for actor in actors.iter() {
            prop_assert_changes!({ clock.inc(*actor) }, clock.len());
        }

        prop_assert_eq!(clock.len(), actors.len());
    }

    #[proptest(fork = false)]
    fn test_len_does_not_change_when_incrementing_known_actors(mut clock: VClock) {
        for actor in clock.clone().actors() {
            prop_assert_does_not_change!(clock.inc(actor), clock.len());
        }
    }

    #[proptest(fork = false)]
    fn test_actors_list_all_the_actors_of_the_clock(
        #[strategy(hash_set(any::<Pubkey>(), 0..10))] actors: HashSet<Pubkey>,
    ) {
        let mut clock = VClock::default();

        for actor in actors.iter() {
            clock.inc(*actor);
        }

        prop_assert_eq!(clock.actors().collect::<HashSet<_>>(), actors);
    }

    #[proptest(fork = false)]
    fn test_get(a: VClock, keys: HashSet<Pubkey>) {
        for actor in a.actors().chain(keys) {
            prop_assert_eq!(a.get(actor), *a.dots.get(&actor).unwrap_or(&0));
        }
    }

    #[proptest(fork = false)]
    fn test_to_bytes_commutativity(key_a: Pubkey, key_b: Pubkey) {
        let mut a = VClock::default();
        let mut b = VClock::default();

        a.inc(key_a);
        a.inc(key_b);
        b.inc(key_b);
        b.inc(key_a);

        prop_assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[proptest(fork = false)]
    fn test_comparable_clocks_are_not_divergent(
        #[strategy(rng())] mut rng: TestRng,
        #[strategy(0..30usize)] n: usize,
        a: VClock,
    ) {
        let mut b = a.clone();

        for _ in 0..(n % a.len()) {
            b.inc(a.actors().choose(&mut rng).unwrap());
        }

        prop_assert!(!a.diverges(&b));
    }

    #[proptest(fork = false)]
    fn test_incomparable_clocks_diverge(a: VClock, b: VClock) {
        prop_assert_eq!(a.diverges(&b), a.partial_cmp(&b).is_none());
    }

    #[proptest(fork = false)]
    fn test_ordering_when_clocks_are_equal(a: VClock) {
        prop_assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
    }

    #[proptest(fork = false)]
    fn test_ordering_when_one_clock_is_newer_than_the_other(key: Pubkey, a: VClock) {
        let mut b = a.clone();
        b.inc(key);

        prop_assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        prop_assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));
    }
}
