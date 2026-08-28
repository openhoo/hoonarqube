use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::callee_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5659 — JWT.Net decoding must verify the token signature.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || callee_name(invocation, source) != Some("Decode")
            || !node_text(invocation, source).contains("verify: false")
        {
            continue;
        }
        issues.push(issue(
            language,
            "S5659",
            "Use only strong cipher algorithms when verifying the signature of this JWT.",
            range_of(invocation, source),
        ));
    }
    issues
}
