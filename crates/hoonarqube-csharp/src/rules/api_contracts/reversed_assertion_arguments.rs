use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets, simple_name,
};
use crate::rules::expressions::{
    callee_name, first_named_child, invocation_arguments, invocation_receiver,
};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3415 — expected values come first in paired assertions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        if !is_paired_assertion(call, source) {
            continue;
        }
        let arguments = invocation_arguments(call);
        if arguments.len() < 2 {
            continue;
        }
        // Named arguments make the expected/actual roles explicit and can
        // appear in either source order. Positional heuristics must not treat
        // an argument's name node as its value.
        if arguments[..2]
            .iter()
            .any(|argument| argument.child_by_field_name("name").is_some())
        {
            continue;
        }
        let first = argument_expression(arguments[0]);
        let second = argument_expression(arguments[1]);
        if !is_expectation_value(first) && is_expectation_value(second) {
            issues.push(issue(
                language,
                "S3415",
                "Make sure these 2 arguments are in the correct order: expected value, actual value.",
                range_from_byte_offsets(first.start_byte(), second.end_byte(), source),
            ));
        }
    }
    issues
}

/// MSTest-style assertion entry points carrying expected/actual pairs.
const PAIRED_ASSERT_METHODS: [&str; 4] = ["AreEqual", "AreNotEqual", "AreSame", "AreNotSame"];

/// Syntactically recognizable NUnit/MSTest assertion entry points. Bare calls
/// remain supported for static imports, but arbitrary custom receivers do not
/// become assertions merely because their method has a familiar name.
fn is_paired_assertion(call: Node<'_>, source: &str) -> bool {
    if !PAIRED_ASSERT_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
        return false;
    }
    invocation_receiver(call).is_none_or(|receiver| {
        matches!(
            simple_name(node_text(receiver, source)),
            "Assert" | "ClassicAssert" | "CollectionAssert"
        )
    })
}

/// Literal kinds that read as hard-coded expectations.
fn is_expectation_value(node: Node<'_>) -> bool {
    if matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "verbatim_string_literal"
            | "raw_string_literal"
            | "null_literal"
            | "default_expression"
    ) {
        return true;
    }
    matches!(
        node.kind(),
        "parenthesized_expression" | "prefix_unary_expression"
    ) && first_named_child(node).is_some_and(is_expectation_value)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3415_flags_all_paired_assert_variants() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreNotEqual(actual, true);\n        CollectionAssert.AreSame(actual, \"lit\");\n        Assert.AreNotSame(actual, 'c');\n        AreEqual(actual, 42);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3415");
        assert_eq!(flagged.len(), 4);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[3].range.start.line, 8);
    }

    #[test]
    fn s3415_ignores_computed_seconds_and_short_calls() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreEqual(actual, Compute());\n        Assert.AreSame(actual, actual);\n        Assert.AreEqual(7, actual);\n        Assert.AreNotEqual(actual);\n        Check.AreEqual(actual, 7);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3415").is_empty());
    }

    #[test]
    fn s3415_handles_expression_actuals_and_modern_constant_values() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreEqual(ReadActual(), null);\n        Assert.AreEqual(actual + 1, -1);\n        Assert.AreEqual(actual, \"\"\"lit\"\"\");\n        Assert.AreEqual((actual), default(object));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3415");
        assert_eq!(flagged.len(), 4);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[3].range.start.line, 8);
    }

    #[test]
    fn s3415_leaves_explicit_named_argument_roles_alone() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreEqual(actual: 42, expected: actual);\n        Custom.AreEqual(value: actual, true);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3415").is_empty());
    }
}
