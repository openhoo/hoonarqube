use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3877 — Dispose/Finalize/Equals/GetHashCode/ToString run
/// during sensitive operations and must not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for callable in collect_kinds(root, &["method_declaration", "destructor_declaration"]) {
        if is_error_tainted(callable) {
            continue;
        }
        let special = callable
            .child_by_field_name("name")
            .is_some_and(|name| SPECIAL_THROW_METHODS.contains(&node_text(name, source)));
        if !special {
            continue;
        }
        for throw_statement in collect_kinds(callable, &["throw_statement"]) {
            if is_error_tainted(throw_statement) {
                continue;
            }
            issues.push(issue(
                language,
                "S3877",
                "Do not throw from this method.",
                range_of(throw_statement),
            ));
        }
    }
    let _ = source;
    issues
}

/// Methods that must never throw once running.
const SPECIAL_THROW_METHODS: [&str; 5] =
    ["Dispose", "Finalize", "Equals", "GetHashCode", "ToString"];
