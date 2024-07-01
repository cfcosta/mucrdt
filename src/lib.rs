mod error;

pub mod collections;
pub mod identifier;
pub mod item;
pub mod prelude;
pub mod testing;
pub mod values;

#[doc(hidden)]
/// This is a hidden module to make the macros defined on this crate available for the users.
pub mod __dependencies {
    pub use blake3::{Hash, Hasher};
    pub use criterion;
    pub use itertools;
    pub use paste;
    pub use proptest;
    pub use rand;
    pub use test_strategy;
    pub use thiserror::Error;
}

#[macro_export]
macro_rules! test_state_crdt_properties {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_crdt_$type:snake>] {
                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };
                use $crate::prelude::{ CvRDT, Result };

                use super::$type;

                #[cfg_attr(coverage_nightly, coverage(off))]
                fn build_state(items: Vec<&$type>) -> Result<$type> {
                    items.into_iter().try_fold(<$type>::default(), |mut acc, el| {
                        acc.merge(el)?;
                        Ok(acc)
                    })
                }

                #[cfg_attr(coverage_nightly, coverage(off))]
                #[test_strategy::proptest(fork = false)]
                fn test_changes_are_applied(a: $type) {
                    let mut b = <$type>::default();
                    b.merge(&a)?;
                    prop_assert_eq!(a, b);
                }

                #[cfg_attr(coverage_nightly, coverage(off))]
                #[test_strategy::proptest(fork = false)]
                fn test_imdepotence(mut a: $type, mut b: $type) {
                    a.merge(&b)?;
                    b.merge(&a)?;
                    prop_assert_eq!(a, b);
                }

                #[cfg_attr(coverage_nightly, coverage(off))]
                #[test_strategy::proptest(fork = false)]
                fn test_commutativity(a: $type, b: $type) {
                    let ab = build_state(vec![&a, &b])?;
                    let ba = build_state(vec![&a, &b])?;

                    prop_assert_eq!(ab, ba);
                }

                #[cfg_attr(coverage_nightly, coverage(off))]
                #[test_strategy::proptest(fork = false)]
                fn test_associativity(a: $type, b: $type, c: $type) {
                    let ab = build_state(vec![&a, &b])?;
                    let bc = build_state(vec![&b, &c])?;

                    let mut ab_c = ab.clone();
                    ab_c.merge(&c)?;

                    let mut a_bc = a.clone();
                    a_bc.merge(&bc)?;

                    prop_assert_eq!(&ab_c, &a_bc);
                    prop_assert_eq!(a_bc, ab_c);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! test_op_crdt_properties_inner {
    ($type: ty, $op_type: ty) => {
        use $crate::__dependencies::proptest::prelude::*;
        use $crate::prelude::{CmRDT, Item, Result};

        fn build_op(items: Vec<&Item<$op_type>>) -> Result<$type> {
            items
                .into_iter()
                .try_fold(<$type>::default(), |mut acc, el| {
                    acc.apply(el)?;
                    Ok(acc)
                })
        }

        #[test_strategy::proptest(fork = false)]
        fn test_imdepotence(op: Item<$op_type>) {
            let mut a = <$type>::default();
            a.apply(&op)?;

            let mut b = a.clone();
            b.apply(&op)?;

            prop_assert_eq!(a, b);
        }

        #[test_strategy::proptest(fork = false)]
        fn test_commutativity(a: Item<$op_type>, b: Item<$op_type>) {
            let ab = build_op(vec![&a, &b])?;
            let ba = build_op(vec![&a, &b])?;

            prop_assert_eq!(ab, ba);
        }
    };
}

#[macro_export]
macro_rules! test_op_crdt_properties {
    ($type: ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_op_crdt_$type:snake>] {
                use super::$type;

                $crate::test_op_crdt_properties_inner!($type, $type);
            }
        }
    };
    ($type: ty, $op_type: ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_op_crdt_$type:snake>] {
                use super::{ $type, $op_type };

                $crate::test_op_crdt_properties_inner!($type, $op_type);
            }
        }
    };
}

#[macro_export]
macro_rules! impl_associate_bytes_types {
    ($type:ty) => {
        impl std::hash::Hash for $type {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.to_bytes().hash(state);
            }
        }

        impl $crate::prelude::FromHex for $type {
            fn from_hex(input: &str) -> Result<Self> {
                let bytes = hex::decode(input)?;
                Self::from_bytes(&bytes)
            }
        }

        impl $crate::prelude::ToHex for $type {
            fn to_hex(&self) -> String {
                hex::encode(&ToBytes::to_bytes(self))
            }
        }
    };
}

#[macro_export]
macro_rules! test_to_bytes {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_to_bytes_$type:snake>] {
                use std::{ collections::hash_map::DefaultHasher, hash::Hasher };

                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };

                use $crate::prelude::*;
                use super::$type;

                test_to_hex!($type);

                #[test]
                fn test_default_is_zero() {
                    assert!(<$type>::default().is_zero());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_zero_is_same_as_zero_bytes(item: $type) {
                    prop_assert_eq!(
                        item.is_zero(),
                        item.to_bytes() == <$type>::default().to_bytes()
                    );
                }

                #[test_strategy::proptest(fork = false)]
                fn test_roundtrip(a: $type) {
                    prop_assert_eq!(a.clone(), <$type>::from_bytes(&a.to_bytes())?);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_output_consistency(a: $type) {
                    prop_assert_eq!(a.to_bytes(), <$type>::from_bytes(&a.to_bytes())?.to_bytes());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_different_on_different_objects(a: $type, b: $type) {
                    prop_assert_eq!(a == b, a.to_bytes() == b.to_bytes());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_hash_consistency(a: $type, b: $type) {
                    prop_assert_eq!(a == b, a.hash_bytes() == b.hash_bytes());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_std_hash_consistency(a: $type, b: $type) {
                    let mut hasher_a = DefaultHasher::new();
                    hasher_a.write(&a.to_bytes());

                    let mut hasher_b = DefaultHasher::new();
                    hasher_b.write(&b.to_bytes());

                    prop_assert_eq!(a.hash_bytes() == b.hash_bytes(), hasher_a.finish() == hasher_b.finish());
                }
            }
        }
    };
}

#[macro_export]
macro_rules! test_to_hex {
    ($type:ty) => {
        $crate::__dependencies::paste::paste! {
            mod [<test_to_hex_$type:snake>] {
                use $crate::__dependencies::{
                    proptest::prelude::*,
                    test_strategy,
                };

                use $crate::prelude::*;
                use super::$type;

                #[test_strategy::proptest(fork = false)]
                fn test_roundtrip(a: $type) {
                    prop_assert_eq!(a.clone(), <$type>::from_hex(&a.to_hex())?);
                }

                #[test_strategy::proptest(fork = false)]
                fn test_output_consistency(a: $type) {
                    prop_assert_eq!(a.to_hex(), <$type>::from_hex(&a.to_hex())?.to_hex());
                }

                #[test_strategy::proptest(fork = false)]
                fn test_is_different_on_different_objects(a: $type, b: $type) {
                    prop_assert_eq!(a == b, a.to_hex() == b.to_hex());
                }
            }
        }
    };
}

#[macro_export]
macro_rules! prop_assert_changes {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        prop_assert_eq!($value, old_value);

        $action;

        prop_assert_ne!($value, old_value);
    };
}

#[macro_export]
macro_rules! prop_assert_does_not_change {
    ($action: expr, $value: expr) => {
        let old_value = $value.clone();

        $action;

        prop_assert_eq!($value, old_value);
    };
}
