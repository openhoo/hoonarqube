use crate::support::WEAK_CIPHER_ALGORITHMS;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::for_each_stmt;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5547_weak_ciphers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ImportFrom(import) = stmt {
            let crypto_module = import.module.as_ref().is_some_and(|module| {
                module.as_str() == "Crypto.Cipher" || module.as_str().ends_with(".Crypto.Cipher")
            });
            if crypto_module
                && import
                    .names
                    .iter()
                    .any(|alias| WEAK_CIPHER_ALGORITHMS.contains(&alias.name.as_str()))
            {
                issues.push(issue_at(
                    "python:S5547",
                    "Replace this weak cipher algorithm with a robust one.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
        }
    });
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let weak_construction = is_call_method(call, "new")
            && dotted_name(&call.func).is_some_and(|p| {
                p.rsplit_once('.')
                    .is_some_and(|(head, _)| WEAK_CIPHER_ALGORITHMS.contains(&head))
            });
        if weak_construction {
            issues.push(issue_at(
                "python:S5547",
                "Replace this weak cipher algorithm with a robust one.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
