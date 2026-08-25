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

// --- migrated from support/mod.rs (S5547) ---
// --- python:S5547 — robust cipher algorithms ------------------------------------

const WEAK_CIPHER_ALGORITHMS: [&str; 6] = ["DES", "DES3", "ARC2", "ARC4", "Blowfish", "IDEA"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5547_flags_weak_cipher_imports_and_constructors() {
        let flagged = concat!(
            "from Crypto.Cipher import DES\n",
            "c = DES.new(key, mode)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5547").len(), 2);
        let clean = concat!(
            "from Crypto.Cipher import AES\n",
            "c = AES.new(key, mode)\n"
        );
        assert!(findings(&scan(clean), "python:S5547").is_empty());
    }
}
