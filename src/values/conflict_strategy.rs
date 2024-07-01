use crate::prelude::Item;

pub struct LastWriteWins;
pub struct FirstWriteWins;

pub trait ConflictStrategy {
    fn resolve<V: Clone + Eq>(&self, a: Item<V>, b: Item<V>) -> Item<V>;
}

impl ConflictStrategy for LastWriteWins {
    fn resolve<V: Clone + Eq>(&self, a: Item<V>, b: Item<V>) -> Item<V> {
        std::cmp::max(a, b)
    }
}

impl ConflictStrategy for FirstWriteWins {
    fn resolve<V: Clone + Eq>(&self, a: Item<V>, b: Item<V>) -> Item<V> {
        std::cmp::min(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    #[proptest(fork = false)]
    fn test_lww(a: Item<u32>, b: Item<u32>) {
        let result = LastWriteWins.resolve(a.clone(), b.clone());

        prop_assert_eq!(result, std::cmp::max(a, b));
    }

    #[proptest(fork = false)]
    fn test_fww(a: Item<u32>, b: Item<u32>) {
        let result = FirstWriteWins.resolve(a.clone(), b.clone());
        prop_assert_eq!(result, std::cmp::min(a, b));
    }
}
