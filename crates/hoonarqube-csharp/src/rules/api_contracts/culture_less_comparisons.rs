use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4058 — two-operand comparisons silently use the current
/// culture instead of a stated comparison mode.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            matches!(callee_name(*call, source), Some("Compare" | "Equals"))
                && invocation_arguments(*call).len() == 2
        })
        .map(|call| {
            issue(
                language,
                "S4058",
                "Use the 'StringComparison' overload of this comparison.",
                range_of(call),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4058_flags_two_argument_equals() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        equal = first.Equals(second);\n        pair = first.Equals(second, StringComparison.Ordinal);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4058");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s4058_three_argument_and_foreign_callees_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        same = string.Compare(first, second, StringComparison.Ordinal) == 0;\n        big = System.Math.Max(left, right);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4058").is_empty());
    }
}
