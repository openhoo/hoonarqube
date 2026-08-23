use crate::support::CUSTOM_CRYPTO_NAME_WORDS;
use crate::support::contains_bitwise_xor;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s2257_custom_cryptography(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            let crypto_named = function
                .name
                .as_str()
                .to_lowercase()
                .split('_')
                .any(|word| {
                    CUSTOM_CRYPTO_NAME_WORDS
                        .iter()
                        .any(|candidate| word.contains(candidate))
                });
            if crypto_named && contains_bitwise_xor(function.body.as_slice()) {
                issues.push(issue_at(
                    "python:S2257",
                    "Use a standard cryptographic library implementation instead of this hand-rolled cipher.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
