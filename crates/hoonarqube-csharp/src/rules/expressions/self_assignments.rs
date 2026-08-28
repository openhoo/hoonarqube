use super::support::binary_operands;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1656 — nothing assigns an expression to itself.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some((left, right)) = binary_operands(assignment) else {
            continue;
        };
        if node_text(left, source).trim() == node_text(right, source).trim() {
            issues.push(issue(
                language,
                "S1656",
                "Remove or correct this useless self-assignment.",
                range_of(left, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1656_flags_only_exact_self_assignments() {
        let bad = analyze_default("class C { void M(int value) { value = value; } }");
        assert_eq!(with_key(&bad, "csharpsquid:S1656").len(), 1);

        let good = analyze_default("class C { void M(int value, int next) { value = next; } }");
        assert!(with_key(&good, "csharpsquid:S1656").is_empty());
    }
}
