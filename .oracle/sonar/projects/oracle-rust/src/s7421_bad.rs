// Hoonarqube oracle fixture: rust:S7421 bad
fn main() {
    let mut twins = vec![(1, 1), (2, 2)];
    twins.sort_by_key(|x| { x.1; }); // Noncompliant: closure returns unit
}
