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
                "Extract this nested ternary into its own statement.",
                range_of(conditional, source),
            ));
        }
    }
    issues
}
