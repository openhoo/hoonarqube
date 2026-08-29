use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets,
};
use crate::rules::expressions::{
    expression_name, invocation_arguments, invocation_receiver, invocation_targets,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3346 — assertions that compute hide failures when stripped.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_debug_assert(call, source) {
            continue;
        }
        for side_effect in invocation_arguments(call)
            .into_iter()
            .flat_map(|argument| argument_side_effects(argument, source))
        {
            issues.push(issue(
                language,
                "S3346",
                "Expressions used in 'Debug.Assert' should not produce side effects.",
                assert_argument_range(side_effect, source),
            ));
        }
    }
    issues
}

fn is_debug_assert(call: Node<'_>, source: &str) -> bool {
    if !invocation_targets(call, source, Some("Debug"), &["Assert"]) {
        return false;
    }
    invocation_receiver(call).and_then(|receiver| expression_name(receiver, source))
        == Some("Debug")
}

fn assert_argument_range(side_effect: Node<'_>, source: &str) -> hoonarqube_ir::Range {
    let bytes = source.as_bytes();
    let start = side_effect.start_byte();
    let end = side_effect.end_byte();
    let expanded_start = if start > 0 && bytes.get(start - 1) == Some(&b'(') {
        start - 1
    } else {
        start
    };
    let expanded_end = if bytes.get(end) == Some(&b')') {
        end + 1
    } else {
        end
    };
    range_from_byte_offsets(expanded_start, expanded_end, source)
}

/// Whether the argument subtree computes something (`f()`, `x++`, `a = b`).
fn argument_side_effects<'a>(argument: Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut side_effects = collect_kinds(
        argument,
        &["invocation_expression", "assignment_expression"],
    );
    side_effects.extend(
        collect_kinds(
            argument,
            &["prefix_unary_expression", "postfix_unary_expression"],
        )
        .into_iter()
        .filter(|unary| {
            let mut cursor = unary.walk();
            unary
                .children(&mut cursor)
                .any(|child| !child.is_named() && matches!(node_text(child, source), "++" | "--"))
        }),
    );
    let side_effect_ids: std::collections::HashSet<usize> =
        side_effects.iter().map(tree_sitter::Node::id).collect();
    side_effects
        .into_iter()
        .filter(|node| {
            !ancestors_of(*node).any(|ancestor| side_effect_ids.contains(&ancestor.id()))
                && !ancestors_of(*node)
                    .take_while(|ancestor| ancestor.id() != argument.id())
                    .any(|ancestor| {
                        matches!(
                            ancestor.kind(),
                            "lambda_expression" | "anonymous_method_expression"
                        )
                    })
        })
        .collect()
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

    #[test]
    fn s3346_requires_an_exact_debug_receiver() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        MyDebug.Assert(Fetch() > 0);\n        System.Diagnostics.Debug.Assert(Fetch() > 0);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3346");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s3346_ignores_work_deferred_inside_lambdas() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Debug.Assert(((System.Func<bool>)(() => Mutate())) != null);\n        Debug.Assert(((System.Func<bool>)(delegate { return Mutate(); })) != null);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3346").is_empty());
    }
}
