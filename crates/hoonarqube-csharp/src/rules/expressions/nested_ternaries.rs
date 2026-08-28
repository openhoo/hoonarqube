use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::has_ancestor_with_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3358 — ternaries do not nest.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        if !is_error_tainted(conditional)
            && has_ancestor_with_kind(conditional, &["conditional_expression"])
        {
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
}
