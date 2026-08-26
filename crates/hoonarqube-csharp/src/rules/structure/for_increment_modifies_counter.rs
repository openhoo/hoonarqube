use super::support::counter_name;
use super::support::for_clauses;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1994 — the increment clause drives the loop counter.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (Some(initializer), _, update) = for_clauses(for_statement) else {
            continue;
        };
        let Some(counter) = counter_name(initializer, source) else {
            continue;
        };
        let modifies_counter = update.is_some_and(|clause| {
            collect_kinds(clause, &["identifier"])
                .iter()
                .any(|identifier| node_text(*identifier, source) == counter)
        });
        if !modifies_counter {
            issues.push(issue(
                language,
                "S1994",
                format!("Update the counter '{counter}' inside this loop's increment."),
                range_of(for_statement, source),
            ));
        }
    }
    issues
}
