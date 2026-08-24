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
        for validation in validation_statements(body, source) {
            issues.push(issue(
                language,
                "S4456",
                "Move this validation out of the iterator; it will not run until enumeration.",
                range_of(validation),
            ));
        }
    }
    issues
}
