// Hoonarqube oracle fixture: rust:S7460 bad
struct A;

impl<'de> serde::de::Visitor<'de> for A {
    type Value = ();

    fn expecting(&self, _: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
      unimplemented!()
    }

    fn visit_string<E>(self, _v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
      unimplemented!()
    }
}

fn main() {}
