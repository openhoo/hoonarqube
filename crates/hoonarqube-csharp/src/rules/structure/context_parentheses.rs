use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3235 — parentheses around return values and arguments
/// cannot change precedence there and are noise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parenthesized in collect_kinds(root, &["parenthesized_expression"]) {
        if is_error_tainted(parenthesized) {
            continue;
        }
        let context = parenthesized.parent().map(|parent| parent.kind());
        if matches!(context, Some("return_statement" | "argument")) {
            issues.push(issue(
                language,
                "S3235",
                "Remove these unnecessary parentheses.",
                range_of(parenthesized, source),
            ));
        }
    }
    issues
}
