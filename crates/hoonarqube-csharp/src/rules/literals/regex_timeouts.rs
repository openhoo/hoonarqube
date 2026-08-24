use super::support::argument_nodes;
use super::support::is_regex_creation;
use super::support::regex_static_pattern;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6444 — every Regex construction and static pattern call
/// carries a timeout.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if !is_regex_creation(creation, source) {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        if !arguments_carry_timeout(arguments, source) {
            issues.push(issue(
                language,
                "S6444",
                "Provide a timeout when constructing this 'Regex'.",
                range_of(creation),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if regex_static_pattern(invocation, source).is_none() {
            continue;
        }
        let timed_out = invocation
            .child_by_field_name("arguments")
            .is_some_and(|arguments| arguments_carry_timeout(arguments, source));
        if !timed_out {
            issues.push(issue(
                language,
                "S6444",
                "Provide a timeout for this 'Regex' call.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// Whether any argument mentions `TimeSpan`, the timeout carrier.
fn arguments_carry_timeout(arguments: Node<'_>, source: &str) -> bool {
    argument_nodes(arguments)
        .iter()
        .any(|argument| node_text(*argument, source).contains("TimeSpan"))
}
