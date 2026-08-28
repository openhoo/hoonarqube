use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3060 — 'this' does not take part in 'is' type tests.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for is_expression in collect_kinds(root, &["is_expression", "is_pattern_expression"]) {
        if is_error_tainted(is_expression) {
            continue;
        }
        let tests_this = is_expression
            .child_by_field_name("left")
            .or_else(|| is_expression.child_by_field_name("expression"))
            .is_some_and(|operand| node_text(operand, source) == "this");
        if tests_this {
            issues.push(issue(
                language,
                "S3060",
                "Offload the code that's conditional on this type test to the appropriate subclass and remove the condition.",
                range_of(is_expression, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3060_flags_this_is_checks_but_not_other_operands() {
        let bad = analyze_default("class C { bool M() => this is C; }");
        assert_eq!(with_key(&bad, "csharpsquid:S3060").len(), 1);

        let good = analyze_default("class C { bool M(object value) => value is C; }");
        assert!(with_key(&good, "csharpsquid:S3060").is_empty());
    }
}
