use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
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
        if !PAIRED_ASSERT_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
            continue;
        }
        let arguments = invocation_arguments(call);
        if arguments.len() < 2 {
            continue;
        }
        let first = argument_expression(arguments[0]);
        let second = argument_expression(arguments[1]);
        if first.kind() == "identifier" && is_expectation_literal(second) {
            issues.push(issue(
                language,
                "S3415",
                "Put the expected value first in this assertion.",
                range_of(call),
            ));
        }
    }
    issues
}

/// MSTest-style assertion entry points carrying expected/actual pairs.
const PAIRED_ASSERT_METHODS: [&str; 4] = ["AreEqual", "AreNotEqual", "AreSame", "AreNotSame"];

/// Literal kinds that read as hard-coded expectations.
fn is_expectation_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "verbatim_string_literal"
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3415_flags_all_paired_assert_variants() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreNotEqual(actual, true);\n        CollectionAssert.AreSame(actual, \"lit\");\n        Check.AreNotSame(actual, 'c');\n        AreEqual(actual, 42);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3415");
        assert_eq!(flagged.len(), 4);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[3].range.start.line, 8);
    }

    #[test]
    fn s3415_ignores_computed_seconds_and_short_calls() {
        let report = analyze_default(
            "class Tests\n{\n    void M(object actual)\n    {\n        Assert.AreEqual(actual, Compute());\n        Assert.AreSame(actual, actual);\n        Assert.AreEqual(7, actual);\n        Assert.AreNotEqual(actual);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3415").is_empty());
    }
}
