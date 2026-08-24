use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2208 — wildcard imports -----------------------------------------

pub(crate) fn check_wildcard_imports(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ImportFrom(import) = stmt
            && import.names.iter().any(|alias| alias.name.as_str() == "*")
        {
            issues.push(issue_at(
                "python:S2208",
                "Name the symbols to import explicitly instead of importing '*'.",
                import.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2208_flags_wildcard_imports() {
        assert_eq!(
            findings(&scan("from m import *\n"), "python:S2208").len(),
            1
        );
        assert!(findings(&scan("from m import thing\n"), "python:S2208").is_empty());
    }
}
