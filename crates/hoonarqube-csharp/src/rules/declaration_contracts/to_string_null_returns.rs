use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2225 — `ToString` returning null breaks formatting and
/// string interpolation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "ToString")
        {
            continue;
        }
        for candidate in collect_kinds(method, &["return_statement", "arrow_expression_clause"]) {
            if first_named_child(candidate).is_some_and(|value| value.kind() == "null_literal") {
                issues.push(issue(
                    language,
                    "S2225",
                    "Do not return null from 'ToString'.",
                    range_of(candidate),
                ));
                break;
            }
        }
    }
    issues
}
