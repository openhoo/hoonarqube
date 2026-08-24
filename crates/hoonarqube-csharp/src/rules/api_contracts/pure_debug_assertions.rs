use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3346 — assertions that compute hide failures when stripped.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !invocation_targets(call, source, Some("Debug"), &["Assert"]) {
            continue;
        }
        let impure = invocation_arguments(call)
            .iter()
            .any(|argument| argument_has_side_effects(*argument, source));
        if impure {
            issues.push(issue(
                language,
                "S3346",
                "Keep side effects out of 'Debug.Assert'.",
                range_of(call),
            ));
        }
    }
    issues
}

/// Whether the argument subtree computes something (`f()`, `x++`, `a = b`).
fn argument_has_side_effects(argument: Node<'_>, source: &str) -> bool {
    !collect_kinds(
        argument,
        &["invocation_expression", "assignment_expression"],
    )
    .is_empty()
        || collect_kinds(
            argument,
            &["prefix_unary_expression", "postfix_unary_expression"],
        )
        .into_iter()
        .any(|unary| {
            let mut cursor = unary.walk();
            unary
                .children(&mut cursor)
                .any(|child| !child.is_named() && matches!(node_text(child, source), "++" | "--"))
        })
}
