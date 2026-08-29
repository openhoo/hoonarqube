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
                .any(|argument| argument_references(*argument, caught, source));
            if !passes {
                issues.push(issue(
                    language,
                    "S6667",
                    "Logging in a catch clause should pass the caught exception as a parameter.",
                    range_of(call, source),
                ));
            }
        }
    }
    issues
}

/// Whether an argument contains a reference to the caught variable. Textual
/// substring matching makes `ex` look present in unrelated names like
/// `messageText`; identifiers preserve the language boundary.
fn argument_references(argument: Node<'_>, caught: &str, source: &str) -> bool {
    collect_kinds(argument, &["identifier"])
        .into_iter()
        .any(|identifier| node_text(identifier, source) == caught)
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6667_requires_an_identifier_reference_not_a_name_substring() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        try { Run(); } catch (Exception ex) { logger.LogError(\"Failed\", messageText); }\n        try { Run(); } catch (Exception ex) { logger.LogError(\"Failed\", Wrap(ex)); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6667");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
