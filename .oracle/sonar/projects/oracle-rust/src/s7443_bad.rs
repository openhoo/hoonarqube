// Hoonarqube oracle fixture: rust:S7443 bad
#[repr(u8)]
enum Opcode {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Div = 3
}

fn int_to_opcode(op: u8) -> Option<Opcode> {
    (op < 4).then_some(unsafe { std::mem::transmute(op) })
}

fn main() {}
