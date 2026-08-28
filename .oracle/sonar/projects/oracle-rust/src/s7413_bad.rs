// Hoonarqube oracle fixture: rust:S7413 bad
async fn foo() {}

fn bar() {
    let x = async {
        foo() // Noncompliant: returns a future that needs to be awaited
    };
}

fn main() {}
