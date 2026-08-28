use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7039 — 'unsafe-inline' or 'unsafe-eval' sources hollow out
/// the Content-Security-Policy.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const UNSAFE_CSP_SOURCES: [&str; 3] = ["unsafe-inline", "unsafe-hashes", "unsafe-eval"];
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(value) = assignment.child_by_field_name("right") else {
            continue;
        };
        if value.kind() != "string_literal" {
            continue;
        }
        let header = node_text(left, source);
        let targets_csp = header.ends_with(".ContentSecurityPolicy")
            || header.contains("[\"Content-Security-Policy\"]");
        let lowered = literal_inner_text(value, source).to_ascii_lowercase();
        let permissive = targets_csp
            && (lowered.contains('*')
                || UNSAFE_CSP_SOURCES
                    .iter()
                    .any(|source_token| lowered.contains(source_token)));
        if permissive {
            issues.push(issue(
                language,
                "S7039",
                "Content Security Policies should be restrictive to mitigate the risk of content injection attacks.",
                range_of(left, source),
            ));
        }
    }
    issues
}
