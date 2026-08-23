use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::is_call_method;
use crate::support::is_static_text_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3329 — unpredictable CBC IVs --------------------------------------

pub(crate) fn check_s3329_static_cbc_iv(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const BLOCK_CIPHERS: [&str; 5] = ["AES", "DES", "DES3", "ARC2", "Blowfish"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
