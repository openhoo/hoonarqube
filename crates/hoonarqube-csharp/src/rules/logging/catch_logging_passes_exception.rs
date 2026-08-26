use super::support::logging_calls;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::invocation_arguments;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6667 — catch-block logging that drops the exception loses
/// the stack trace.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for clause in collect_kinds(root, &["catch_clause"]) {
        if is_error_tainted(clause) {
            continue;
        }
        let Some(caught) = caught_exception_name(clause, source) else {
            continue;
        };
        let Some(body) = clause.child_by_field_name("body") else {
            continue;
        };
        for call in logging_calls(body, source) {
            let passes = invocation_arguments(call)
                .iter()
                .any(|argument| node_text(*argument, source).contains(caught));
            if !passes {
                issues.push(issue(
                    language,
                    "S6667",
                    "Pass the caught exception to this log call.",
                    range_of(call, source),
                ));
            }
        }
    }
    issues
}

/// The declared variable name of a catch clause (`catch (Exception ex)`).
fn caught_exception_name<'a>(clause: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut cursor = clause.walk();
    clause
        .children(&mut cursor)
        .find(|child| child.kind() == "catch_declaration")
        .and_then(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
}
