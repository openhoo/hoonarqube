use super::support::enclosing_callable;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3358 — ternaries do not nest.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        let owner = enclosing_callable(conditional).map(|callable| callable.id());
        let nested_in_same_callable = ancestors_of(conditional).any(|ancestor| {
            ancestor.kind() == "conditional_expression"
                && enclosing_callable(ancestor).map(|callable| callable.id()) == owner
        });
        if !is_error_tainted(conditional) && nested_in_same_callable {
            issues.push(issue(
                language,
                "S3358",
                "Extract this nested ternary operation into an independent statement.",
                range_of(conditional, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3358_flags_only_nested_ternaries() {
        let bad = analyze_default(
            "class C { int M(bool first, bool second) => first ? (second ? 1 : 2) : 3; }",
        );
        assert_eq!(with_key(&bad, "csharpsquid:S3358").len(), 1);

        let good = analyze_default("class C { int M(bool first) => first ? 1 : 2; }");
        assert!(with_key(&good, "csharpsquid:S3358").is_empty());
    }

    #[test]
    fn s3358_does_not_cross_lambda_scope() {
        let report = analyze_default(
            "class C { object M(bool outer, bool inner) => outer ? new System.Func<int>(() => inner ? 1 : 2) : null; }",
        );
        assert!(with_key(&report, "csharpsquid:S3358").is_empty());
    }
}
