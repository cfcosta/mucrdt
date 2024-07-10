use super::step::Step;
use proptest::{ prelude::*, collection::vec };

/// Represents a proof in the  Patricia Forestry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof(pub Vec<Step>);

impl PartialOrd for Proof {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Compare the lengths of the proof vectors first
        match self.0.len().partial_cmp(&other.0.len()) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }

        // If lengths are equal, compare each step
        for (self_step, other_step) in self.0.iter().zip(other.0.iter()) {
            match self_step.partial_cmp(other_step) {
                Some(core::cmp::Ordering::Equal) => continue,
                ord => return ord,
            }
        }

        // If all steps are equal, the proofs are equal
        Some(core::cmp::Ordering::Equal)
    }
}

impl Arbitrary for Proof {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(max_depth: Self::Parameters) -> Self::Strategy {
        vec(any::<Step>(), 0..=max_depth)
            .prop_map(Proof)
            .boxed()
    }
}

impl Default for Proof {
    fn default() -> Self {
        Proof(Vec::new())
    }
}

impl Proof {
    pub fn new() -> Self {
        Self::default()
    }
}
