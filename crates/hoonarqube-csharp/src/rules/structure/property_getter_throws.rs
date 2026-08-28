use super::support::accessor_keyword;
use super::support::accessors_of;
use super::support::body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2372 — property getters do not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        for accessor in accessors_of(property) {
            if accessor_keyword(accessor, source) != "get" {
                continue;
            }
            for throw_statement in body_of(accessor)
                .into_iter()
                .flat_map(|body| collect_kinds(body, &["throw_statement"]))
                .filter(|throw_statement| {
                    !collect_kinds(*throw_statement, &["object_creation_expression"])
                        .into_iter()
                        .filter_map(|creation| creation.child_by_field_name("type"))
                        .any(|exception_type| {
                            matches!(
                                simple_name(node_text(exception_type, source)),
                                "NotImplementedException"
                                    | "NotSupportedException"
                                    | "InvalidOperationException"
                            )
                        })
                })
            {
                issues.push(issue(
                    language,
                    "S2372",
                    "Remove the exception throwing from this property getter, or refactor the property into a method.",
                    range_of(throw_statement, source),
                ));
            }
        }
    }
    issues
}
