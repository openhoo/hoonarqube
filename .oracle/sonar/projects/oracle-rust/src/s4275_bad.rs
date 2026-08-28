// Hoonarqube oracle fixture: rust:S4275 bad
struct MyStruct {
    field1: i32,
    field2: i32,
}

impl MyStruct {
    // Incorrectly accessing field2 instead of field1
    fn field1(&self) -> i32 {
        self.field2
    }

    fn field2(&self) -> i32 {
        self.field2
    }
}

fn main() {}
