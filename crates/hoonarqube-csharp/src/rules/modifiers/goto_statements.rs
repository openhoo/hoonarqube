use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S907 — gotos destroy structured control flow.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["goto_statement"]) {
        issues.push(issue(
            language,
            "S907",
            "Replace this 'goto' with structured control flow.",
            range_of(statement, source),
        ));
    }
    issues
}
