// Hoonarqube oracle fixture: rust:S7419 good

struct Recorder;

impl Recorder {
    fn write(&self, _message: &str) {}
}

fn main() {
    Recorder.write("done");
}
