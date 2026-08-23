use crate::support::call_path_matches;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4787 — encrypting data is security-sensitive --------------------

pub(crate) fn check_s4787_encrypting_data(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const ENCRYPTION_APIS: [&str; 4] = [
        "cryptography.fernet.Fernet",
        "cryptography.hazmat.primitives.ciphers.Cipher",
        "nacl.secret.SecretBox",
        "nacl.public.PrivateKey",
    ];
    const PYCRYPTO_CIPHERS: [&str; 8] = [
        "AES",
        "DES",
        "DES3",
        "Blowfish",
        "ARC2",
        "ARC4",
        "ChaCha20",
        "PKCS1_v1_5",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let encrypts = is_call_method(call, "Fernet")
            || call_path_matches(call, &ENCRYPTION_APIS, &["Crypto.Cipher."], &[])
            || (is_call_method(call, "new")
                && dotted_name(&call.func).is_some_and(|p| {
                    p.rsplit_once('.')
                        .is_some_and(|(head, _)| PYCRYPTO_CIPHERS.contains(&head))
                }));
        if encrypts {
            issues.push(issue_at(
                "python:S4787",
                "Make sure that encrypting data is safe here.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
