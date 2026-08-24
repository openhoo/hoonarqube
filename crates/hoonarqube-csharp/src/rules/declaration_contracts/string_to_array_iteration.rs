use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3456 — converting a string to a char array only to index or
/// iterate it allocates for nothing; strings are enumerable already.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Whether the node converts through `ToCharArray()`/`ToArray()`.
    fn conversion_call(node: Node<'_>, source: &str) -> bool {
        node.kind() == "invocation_expression"
            && matches!(callee_name(node, source), Some("ToCharArray" | "ToArray"))
    }

    let mut issues = Vec::new();
    for access in collect_kinds(root, &["element_access_expression"]) {
        if is_error_tainted(access) {
            continue;
        }
        if first_named_child(access).is_some_and(|receiver| conversion_call(receiver, source)) {
            issues.push(issue(
                language,
                "S3456",
                "Index the string directly instead of this array conversion.",
                range_of(access),
            ));
        }
    }
    foreach_conversion_issues(root, source, language, &mut issues, conversion_call);
    issues
}

/// The foreach half of csharpsquid:S3456.
fn foreach_conversion_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
    conversion_call: impl Fn(Node<'_>, &str) -> bool,
) {
    for foreach_statement in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(foreach_statement) {
            continue;
        }
        let mut cursor = foreach_statement.walk();
        let iterates_conversion = foreach_statement
            .children(&mut cursor)
            .any(|child| conversion_call(child, source));
        if iterates_conversion {
            issues.push(issue(
                language,
                "S3456",
                "Iterate the string directly instead of this array conversion.",
                range_of(foreach_statement),
            ));
        }
    }
}
