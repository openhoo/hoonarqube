// Hoonarqube oracle fixture: rust:S7462 bad
use std::mem;

fn may_panic(v: Vec<i32>) -> Vec<i32> { v }

#[allow(deprecated, invalid_value)]
fn myfunc(v: &mut Vec<i32>) {
    let taken_v = unsafe { mem::replace(v, mem::uninitialized()) }; // Noncompliant
    let new_v = may_panic(taken_v); // undefined behavior on panic
    mem::forget(mem::replace(v, new_v));
}

fn main() {}
