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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3346_flags_assignments_and_prefix_decrements() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Debug.Assert((total = Compute()) > 0);\n        Debug.Assert(--pending == 0);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3346");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3346_ignores_trace_assert_and_pure_debug_calls() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Trace.Assert(Fetch() > 0);\n        Debug.WriteLine(Fetch());\n        Debug.Assert(total == expected);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3346").is_empty());
    }
}
