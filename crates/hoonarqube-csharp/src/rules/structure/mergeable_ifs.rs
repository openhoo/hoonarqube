use super::support::else_alternative;
use super::support::embedded_bodies;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1066 — an `else`-less `if` holding exactly one nested `if`
/// merges into a single condition.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn mergeable_block(block: Node<'_>) -> bool {
        let statements = embedded_bodies(block);
        statements.len() == 1
            && statements[0].kind() == "if_statement"
            && else_alternative(statements[0]).is_none()
    }
    let mut issues = Vec::new();
    for if_statement in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(if_statement) || else_alternative(if_statement).is_some() {
            continue;
        }
        let Some(consequence) = embedded_bodies(if_statement).first().copied() else {
            continue;
        };
        let mergeable = match consequence.kind() {
            "if_statement" => else_alternative(consequence).is_none(),
            "block" => mergeable_block(consequence),
            _ => false,
        };
        if mergeable {
            issues.push(issue(
                language,
                "S1066",
                "Merge this if statement with the nested one.",
                range_of(if_statement, source),
            ));
        }
    }
    issues
}
