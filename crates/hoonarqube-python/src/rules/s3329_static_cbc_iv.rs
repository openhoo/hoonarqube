use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::is_call_method;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3329 — unpredictable CBC IVs --------------------------------------

pub(crate) fn check_s3329_static_cbc_iv(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const BLOCK_CIPHERS: [&str; 5] = ["AES", "DES", "DES3", "ARC2", "Blowfish"];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let block_cipher_new = is_call_method(call, "new")
            && dotted_name(&call.func).is_some_and(|p| {
                p.rsplit_once('.')
                    .is_some_and(|(head, _)| BLOCK_CIPHERS.contains(&head))
            });
        let cbc_mode = is_call_method(call, "CBC");
        let static_iv = keyword_value(&call.arguments, "iv")
            .or_else(|| call.arguments.args.first().filter(|_| cbc_mode))
            .is_some_and(is_static_text_literal);
        if (block_cipher_new || cbc_mode) && static_iv {
            issues.push(issue_at(
                "python:S3329",
                "Generate this cipher IV randomly for every encryption.",
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
    fn s3329_flags_static_cbc_ivs() {
        let flagged = concat!(
            "AES.new(k, AES.MODE_CBC, iv=b\"0123456789abcdef\")\n",
            "c = Cipher(a, modes.CBC(b\"staticiv12345\"))\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S3329").len(), 2);
        assert!(
            findings(
                &scan("AES.new(k, AES.MODE_CBC, iv=os.urandom(16))\n"),
                "python:S3329"
            )
            .is_empty()
        );
    }
}
