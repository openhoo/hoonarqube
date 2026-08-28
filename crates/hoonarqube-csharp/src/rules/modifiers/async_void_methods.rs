use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3168 — async methods returning void swallow exceptions and
/// cannot be awaited.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let Some(returns) = method
            .child_by_field_name("returns")
            .filter(|returns| node_text(*returns, source).trim() == "void")
        else {
            continue;
        };
        issues.push(issue(
            language,
            "S3168",
            "Return 'Task' instead.",
            range_of(returns, source),
        ));
    }
    issues
}
