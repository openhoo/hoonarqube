// Hoonarqube oracle fixture: rust:S7423 bad
fn foo() {}
fn bar() {}
fn baz() {}

fn main() {
    if {
        foo();
    } == {
        bar();
    } {
        baz();
    } // Noncompliant: Comparing unit values.
}
