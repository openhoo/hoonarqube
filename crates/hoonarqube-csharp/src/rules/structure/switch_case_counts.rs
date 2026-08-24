use super::support::switch_body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1301 — switches replace at least three-way dispatch;
/// smaller ones read better as `if`/`else`.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        let case_labels = collect_kinds(body, &["case"]).len();
        if case_labels < 3 {
            issues.push(issue(
                language,
                "S1301",
                "Replace this switch with an 'if'/'else' chain; it has fewer than three cases.",
                range_of(switch_statement),
            ));
        }
    }
    issues
}
