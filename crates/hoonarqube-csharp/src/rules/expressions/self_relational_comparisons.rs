use super::support::{comparisons, operator_of, resolved_identifier_type};
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2198 — comparisons against constants outside an operand
/// type's range are constant results.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    comparisons(root)
        .into_iter()
        .filter(|(expression, _, _)| {
            matches!(operator_of(*expression), Some("<" | ">" | "<=" | ">="))
        })
        .filter(|(_, left, right)| {
            (node_text(*right, source) == "double.MaxValue"
                && resolved_identifier_type(*left, source) == Some("float"))
                || (node_text(*left, source) == "double.MaxValue"
                    && resolved_identifier_type(*right, source) == Some("float"))
        })
        .map(|(expression, _, _)| {
            issue(
                language,
                "S2198",
                "Comparison to this constant is useless; the constant is outside the range of type 'float'",
                range_of(expression, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2198_flags_float_comparisons_to_double_limits() {
        let bad = analyze_default(
            "class C { bool M(float value) => value <= double.MaxValue || value > double.MaxValue; }",
        );
        let found = with_key(&bad, "csharpsquid:S2198");
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|issue| issue.message.ends_with("type 'float'"))
        );

        let good = analyze_default("class C { bool M(double value) => value <= double.MaxValue; }");
        assert!(with_key(&good, "csharpsquid:S2198").is_empty());
    }

    #[test]
    fn s2198_does_not_leak_parameter_types_between_methods() {
        let report = analyze_default(
            "class C { bool Float(float value) => value <= double.MaxValue; bool Wide(double value) => value <= double.MaxValue; }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2198").len(), 1);
    }
}
