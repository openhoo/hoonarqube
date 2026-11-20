#![allow(dead_code)]
use std::num::NonZeroUsize;

fn original() -> Option<std::char::ToUppercase> {
    let result = Some('a').map(|s| s.to_uppercase());
    result
}
fn renamed() -> Option<std::char::ToUppercase> {
    let result = Some('a').map(|c| c.to_uppercase());
    result
}
fn reindented() -> Option<std::char::ToUppercase> {
        let result = Some('a').map(|s| s.to_uppercase());
    result
}
fn multiline() -> Option<std::char::ToUppercase> {
    Some('a')
        .map(|letter|
            letter
                .to_uppercase()
        )
}
fn moved() -> Option<std::char::ToLowercase> {
    Some('A').map(move |c| c.to_lowercase())
}
fn block() -> Option<std::char::ToUppercase> {
    Some('a').map(|c| { c.to_uppercase() })
}
fn typed(value: Option<char>) -> Option<std::char::ToUppercase> {
    value.map(|c| c.to_uppercase())
}
fn width() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(12)
}
fn nonzero(value: Option<NonZeroUsize>) -> Option<usize> {
    value.map(|n| n.get())
}
fn owned(value: Option<String>) -> Option<usize> {
    value.map(|s| s.len())
}
fn adjusted(value: Option<&String>) -> Option<String> {
    value.map(|s| s.to_uppercase())
}
fn captured(other: char) -> Option<bool> {
    Some('a').map(|c| c == other)
}
fn different(other: char) -> Option<std::char::ToUppercase> {
    Some('a').map(|_| other.to_uppercase())
}
fn reference() -> Option<std::char::ToUppercase> {
    Some('a').map(char::to_uppercase)
}
fn main() {
    assert_eq!(original().unwrap().to_string(), renamed().unwrap().to_string());
    assert_eq!(original().unwrap().to_string(), reindented().unwrap().to_string());
    assert_eq!(original().unwrap().to_string(), multiline().unwrap().to_string());
    assert_eq!(original().unwrap().to_string(), reference().unwrap().to_string());
}
