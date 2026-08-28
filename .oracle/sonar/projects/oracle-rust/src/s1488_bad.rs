// Hoonarqube oracle fixture: rust:S1488 bad
fn compute_duration_in_milliseconds(hours: u32, minutes: u32, seconds: u32) -> u32 {
    let duration = (((hours * 60) + minutes) * 60 + seconds) * 1000;
    duration
}

fn main() {}
