// Hoonarqube oracle fixture: rust:S7461 bad
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
struct Key(String);
impl Hash for Key { fn hash<H: Hasher>(&self, state: &mut H) { self.0.hash(state); } }
impl Borrow<str> for Key { fn borrow(&self) -> &str { &self.0 } }
impl Borrow<[u8]> for Key { fn borrow(&self) -> &[u8] { self.0.as_bytes() } }

fn main() {}
