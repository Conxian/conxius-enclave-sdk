use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serializer};
use std::fmt;

struct ByteArrayVisitor<const N: usize>;

impl<const N: usize> ByteArrayVisitor<N> {
    fn new() -> Self {
        ByteArrayVisitor
    }
}

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a byte array of length {N}")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut arr = [0u8; N];
        for (i, byte) in arr.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        Ok(arr)
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let mut arr = [0u8; N];
        if v.len() != N {
            return Err(serde::de::Error::invalid_length(v.len(), &self));
        }
        arr.copy_from_slice(v);
        Ok(arr)
    }
}

fn serialize_big_array<const N: usize, S: Serializer>(
    data: &[u8; N],
    s: S,
) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        let mut t = s.serialize_tuple(N)?;
        for b in data {
            t.serialize_element(b)?;
        }
        t.end()
    } else {
        s.serialize_bytes(data)
    }
}

fn deserialize_big_array<'de, const N: usize, D: Deserializer<'de>>(
    d: D,
) -> Result<[u8; N], D::Error> {
    if d.is_human_readable() {
        d.deserialize_tuple(N, ByteArrayVisitor::<N>::new())
    } else {
        d.deserialize_bytes(ByteArrayVisitor::<N>::new())
    }
}

// Concrete helpers for use in #[serde] attributes

pub mod arr48 {
    use super::*;

    pub fn serialize<S: Serializer>(data: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        serialize_big_array::<48, S>(data, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        deserialize_big_array::<48, D>(d)
    }
}

pub mod arr96 {
    use super::*;

    pub fn serialize<S: Serializer>(data: &[u8; 96], s: S) -> Result<S::Ok, S::Error> {
        serialize_big_array::<96, S>(data, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 96], D::Error> {
        deserialize_big_array::<96, D>(d)
    }
}

pub mod arr48_vec {
    use serde::{Deserializer, Serializer};

    #[derive(Debug, Clone, Copy)]
    struct Arr48Ref<'a>(&'a [u8; 48]);

    impl serde::Serialize for Arr48Ref<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            super::serialize_big_array::<48, S>(self.0, s)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct Arr48([u8; 48]);

    impl<'de> serde::Deserialize<'de> for Arr48 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            super::deserialize_big_array::<48, D>(d).map(Arr48)
        }
    }

    pub fn serialize<S: Serializer>(data: &[[u8; 48]], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(data.len()))?;
        for arr in data {
            seq.serialize_element(&Arr48Ref(arr))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 48]>, D::Error> {
        use serde::de::SeqAccess;
        struct Arr48VecVisitor;
        impl<'de> serde::de::Visitor<'de> for Arr48VecVisitor {
            type Value = Vec<[u8; 48]>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a sequence of 48-byte arrays")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(arr) = seq.next_element::<Arr48>()? {
                    v.push(arr.0);
                }
                Ok(v)
            }
        }
        d.deserialize_seq(Arr48VecVisitor)
    }
}
