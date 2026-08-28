use crate::engine::file_context::FileContext;
use crate::support::dotted_name_parent_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4787 — encrypting data is security-sensitive --------------------

pub(crate) fn check_s4787_encrypting_data(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
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
    for call in &file_ctx.calls {
        let encrypts = crate::support::is_call_method(call, "new")
            && dotted_name_parent_in(&call.func, &PYCRYPTO_CIPHERS);
        if encrypts {
            issues.push(issue_at(
                "python:S4787",
                "Make sure that encrypting data is safe here.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4787_flags_encryption_api_constructions() {
        let flagged = concat!(
            "aes = AES.new(key)\n",
            "f = Fernet(secret)\n",
            "c = cryptography.hazmat.primitives.ciphers.Cipher(a, b)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4787").len(), 1);
        assert!(
            findings(
                &scan("digest = hashlib.sha256(b\"data\")\n"),
                "python:S4787"
            )
            .is_empty()
        );
    }
}
