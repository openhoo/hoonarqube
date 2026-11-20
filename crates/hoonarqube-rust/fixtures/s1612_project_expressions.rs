use std::thread;
fn ripgrep() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(12)
}
fn rayon() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
fn main() { assert!(ripgrep() > 0 && rayon() > 0); }
