// Hoonarqube oracle fixture: rust:S7419 bad
use std::io;
fn foo<W: io::Write>(w: &mut W) -> io::Result<()> {
    w.write(b"foo")?; // Noncompliant: This might not write the entire buffer.
    Ok(())
}

fn bar<R: io::Read>(r: &mut R, buffer: &mut [u8]) -> io::Result<()> {
    r.read(buffer)?; // Noncompliant: This might not read the entire buffer.
    Ok(())
}

fn main() {}
