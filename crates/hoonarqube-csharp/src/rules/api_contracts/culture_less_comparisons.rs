use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4058 — two-operand comparisons silently use the current
/// culture instead of a stated comparison mode.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            let arguments = invocation_arguments(*call);
            let function_text =
                invocation_function(*call).map_or("", |function| node_text(function, source));
            matches!(callee_name(*call, source), Some("Compare" | "Equals"))
                && matches!(function_text, "string.Compare" | "string.Equals")
                && !arguments.is_empty()
                && !arguments.iter().any(|argument| {
                    let text = node_text(*argument, source);
                    [
                        "StringComparison",
                        "StringComparer",
                        "Ordinal",
                        "Invariant",
                        "CultureInfo",
                        "IgnoreCase",
                    ]
                    .iter()
                    .any(|token| text.contains(token))
                })
        })
        .map(|call| {
            let method = callee_name(call, source).unwrap_or("comparison");
            issue(
                language,
                "S4058",
                format!(
                    "Change this call to 'string.{method}' to an overload that accepts a 'StringComparison' as a parameter."
                ),
                range_of(call, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4058_flags_culture_less_equals_and_spares_ordinal() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        equal = first.Equals(second);\n        pair = first.Equals(second, StringComparison.Ordinal);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4058");
        assert!(flagged.is_empty());
    }

    #[test]
    fn s4058_three_argument_and_foreign_callees_stay_unflagged() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        same = string.Compare(first, second, StringComparison.Ordinal) == 0;\n        big = System.Math.Max(left, right);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4058").is_empty());
    }
}
