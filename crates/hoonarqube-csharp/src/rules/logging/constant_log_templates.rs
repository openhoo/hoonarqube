use super::support::{caught_exception_name, logging_calls};
use crate::CsLanguage;
use crate::cst::{ancestors_of, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    creation_type_text, invocation_arguments, resolved_identifier_type,
};
use crate::rules::literals::{argument_expression, is_string_literal};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2629 — interpolated or computed templates defeat structured
/// logging; only constant templates can be parsed by log backends.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    logging_calls(root, source)
        .into_iter()
        .filter_map(|call| message_template_expression(call, source))
        .filter(|expression| !is_string_literal(*expression))
        .map(|expression| {
            let message = if expression.kind() == "interpolated_string_expression" {
                "Don't use string interpolation in logging message templates."
            } else {
                "Don't use string concatenation in logging message templates."
            };
            issue(language, "S2629", message, range_of(expression, source))
        })
        .collect()
}

/// The expression occupying the message-template slot of a logging call.
/// Standard shapes put the template first (`Log*(message, args…)`) or after
/// leading metadata (`Log*(exception, message, args…)`,
/// `Log*(eventId, exception, message, args…)`), so the template is the first
/// argument that is either string-shaped — the template itself, constant or
/// interpolated — or not metadata. When every argument is metadata the
/// trailing argument still binds the template slot (Serilog-style `Log(ex)`).
fn message_template_expression<'a>(call: Node<'a>, source: &'a str) -> Option<Node<'a>> {
    let arguments = invocation_arguments(call);
    arguments
        .iter()
        .map(|argument| argument_expression(*argument))
        .find(|expression| {
            is_string_literal(*expression)
                || expression.kind() == "interpolated_string_expression"
                || !is_call_metadata(*expression, source)
        })
        .or_else(|| {
            arguments
                .last()
                .map(|argument| argument_expression(*argument))
        })
}

/// Whether an argument occupies a metadata slot (exception, event id, or log
/// level) rather than the message-template slot.
fn is_call_metadata(expression: Node<'_>, source: &str) -> bool {
    match expression.kind() {
        "object_creation_expression" => {
            is_metadata_type(simple_name(creation_type_text(expression, source)))
        }
        "identifier" => {
            resolved_identifier_type(expression, source)
                .is_some_and(|ty| is_metadata_type(simple_name(ty.trim_end_matches(['?', ']']))))
                || is_caught_exception(expression, source)
        }
        "member_access_expression" => resolved_identifier_type(expression, source)
            .or_else(|| qualifier_type(expression, source))
            .is_some_and(|ty| is_metadata_type(simple_name(ty.trim_end_matches(['?', ']'])))),
        _ => false,
    }
}

/// Type spelling of a member access qualifier (`LogLevel` of
/// `LogLevel.Warning`, `Exception` of `ex.InnerException`): the declared type
/// when the qualifier resolves, else the qualifier's own spelling.
fn qualifier_type<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    let qualifier = expression.child_by_field_name("expression")?;
    if qualifier.kind() == "identifier" {
        resolved_identifier_type(qualifier, source).or(Some(node_text(qualifier, source)))
    } else {
        resolved_identifier_type(qualifier, source)
    }
}

/// Whether the identifier names the exception variable of an enclosing
/// `catch` clause (`catch (Exception ex) { … logger.LogError(ex, …) }`).
fn is_caught_exception(identifier: Node<'_>, source: &str) -> bool {
    let name = node_text(identifier, source);
    ancestors_of(identifier)
        .filter(|ancestor| ancestor.kind() == "catch_clause")
        .any(|clause| caught_exception_name(clause, source) == Some(name))
}

/// Type names that never carry the message template: exceptions plus the
/// `EventId`/`LogLevel` metadata of the standard logging shapes.
fn is_metadata_type(name: &str) -> bool {
    name.ends_with("Exception") || matches!(name, "EventId" | "LogLevel")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2629_accepts_verbatim_and_raw_static_templates() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        logger.LogInformation(@\"Value {Value}\", value);\n        logger.LogInformation(\"\"\"Value {Value}\"\"\", value);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2629").is_empty());
    }
}
