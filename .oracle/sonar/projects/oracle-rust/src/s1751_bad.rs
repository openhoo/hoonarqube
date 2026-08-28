// Hoonarqube oracle fixture: rust:S1751 bad
fn main() {
    let mut x = 0;
    loop {
        x += 1;
        if x == 1 {
            return;
        }
        break;
    }
}
