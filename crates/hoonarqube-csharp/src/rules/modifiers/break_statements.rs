use super::support::has_ancestor_with_kind;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1227 — bare `break`s belong to loops and switch sections
/// only.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["break_statement"]) {
        let legal_home = has_ancestor_with_kind(
            statement,
            &[
                "switch_section",
                "for_statement",
                "foreach_statement",
                "while_statement",
                "do_statement",
            ],
        );
        if !legal_home {
            issues.push(issue(
                language,
                "S1227",
                "Remove this 'break'; it exits neither a loop nor a switch section.",
                range_of(statement),
            ));
        }
    }
    issues
}
