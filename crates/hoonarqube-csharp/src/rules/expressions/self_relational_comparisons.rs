use super::support::{comparisons, operator_of};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2198 — comparisons against constants outside an operand
/// type's range are constant results.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let float_names: std::collections::HashSet<&str> = collect_kinds(root, &["parameter"])
        .into_iter()
        .filter(|parameter| {
            parameter
                .child_by_field_name("type")
                .is_some_and(|ty| node_text(ty, source) == "float")
        })
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();

    comparisons(root)
        .into_iter()
        .filter(|(expression, _, _)| {
            matches!(operator_of(*expression), Some("<" | ">" | "<=" | ">="))
        })
        .filter(|(_, left, right)| {
            (float_names.contains(node_text(*left, source))
                && node_text(*right, source) == "double.MaxValue")
                || (float_names.contains(node_text(*right, source))
                    && node_text(*left, source) == "double.MaxValue")
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
}
