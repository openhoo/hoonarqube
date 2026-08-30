// Hoonarqube oracle fixture: rust:S6466 good

use std::ops::Index;

struct Rows([i32; 2]);

impl Index<&str> for Rows {
    type Output = [i32; 2];

    fn index(&self, _index: &str) -> &Self::Output {
        &self.0
    }
}

fn main() {
    let rows = Rows([1, 2]);
    println!("{}", rows["first"][1]);
}
