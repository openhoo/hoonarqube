use super::support::CALLABLE_BODY_OWNER_KINDS;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1821 — switch statements do not nest inside other switches.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let nested_in_switch = ancestors_of(switch_statement)
            .take_while(|ancestor| !CALLABLE_BODY_OWNER_KINDS.contains(&ancestor.kind()))
            .any(|ancestor| ancestor.kind() == "switch_statement");
        if nested_in_switch {
            issues.push(issue(
                language,
                "S1821",
                "Refactor this nested 'switch' into a separate method.",
                range_of(switch_statement),
            ));
        }
    }
    issues
}
