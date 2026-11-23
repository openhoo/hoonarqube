//! Limit notebook collections while reading them, before allocating an entire
//! array of cell objects or source strings.
use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use std::{fmt, marker::PhantomData};

pub(super) struct Bounded<T, const N: usize>(pub Vec<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Items<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Items<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array with at most {N} entries")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut values = Vec::new();
                while let Some(item) = seq.next_element()? {
                    if values.len() == N {
                        return Err(de::Error::custom(format!(
                            "notebook array exceeds {N} entries"
                        )));
                    }
                    values.push(item);
                }
                Ok(Bounded(values))
            }
        }
        deserializer.deserialize_seq(Items(PhantomData))
    }
}
