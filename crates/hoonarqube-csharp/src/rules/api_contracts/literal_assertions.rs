use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2701 — literal assertions pass regardless of the code under
/// test.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const TRUE_ASSERT_METHODS: [&str; 2] = ["IsTrue", "True"];
    const FALSE_ASSERT_METHODS: [&str; 2] = ["IsFalse", "False"];
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let Some(name) = callee_name(call, source) else {
            continue;
        };
        let Some(first) = invocation_arguments(call).first().copied() else {
            continue;
        };
        let expression = argument_expression(first);
        let literal = if expression.kind() == "boolean_literal" {
            node_text(expression, source)
        } else {
            ""
        };
        let mismatched = (TRUE_ASSERT_METHODS.contains(&name) && literal == "true")
            || (FALSE_ASSERT_METHODS.contains(&name) && literal == "false");
        if mismatched {
            issues.push(issue(
                language,
                "S2701",
                "Remove the literal from this assertion.",
                range_of(call),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2701_contrary_literals_and_leading_variables_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.IsTrue(false);\n        widget.IsFalse(true);\n        Assert.IsTrue(ready, \"because\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2701").is_empty());
    }

    #[test]
    fn s2701_flags_classic_true_false_assertion_names() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.True(true);\n        Assert.False(false);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2701").len(), 2);
    }
}
