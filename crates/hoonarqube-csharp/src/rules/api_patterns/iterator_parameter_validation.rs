use super::support::validation_statements;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4456 — iterators defer their whole body until
/// enumeration, so argument validation inside them surfaces far from
/// the buggy call site.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(body) = body_of(method) else {
            continue;
        };
        if collect_kinds(body, &["yield_statement"]).is_empty() {
            continue;
        }
        if !validation_statements(body, source).is_empty() {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4456",
                "Split this method into two, one handling parameters check and the other handling the iterator.",
                range_of(name, source),
            ));
        }
    }
    issues
}
