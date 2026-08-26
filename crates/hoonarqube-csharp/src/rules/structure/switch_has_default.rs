use super::support::switch_body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::subtree_contains_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S131 — every `switch` carries a `default` clause.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let has_default = switch_body_of(switch_statement)
            .is_some_and(|body| subtree_contains_kind(body, "default"));
        if !has_default {
            issues.push(issue(
                language,
                "S131",
                "Add a 'default' clause to this switch.",
                range_of(switch_statement, source),
            ));
        }
    }
    issues
}
