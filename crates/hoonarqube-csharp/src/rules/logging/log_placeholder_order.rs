use super::support::logging_calls;
use super::support::template_argument;
use super::support::template_placeholder_spans;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_from_byte_offsets};
use crate::rules::expressions::invocation_arguments;
use crate::rules::literals::{argument_expression, literal_inner_offset};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6673 — when placeholder and argument names prove a
/// transposition, the placeholders must follow the argument order.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        let placeholders = template_placeholder_spans(template);
        let arguments: Vec<Option<&str>> = invocation_arguments(call)
            .iter()
            .skip(1)
            .map(|argument| {
                let expression = argument_expression(*argument);
                (expression.kind() == "identifier").then(|| node_text(expression, source))
            })
            .collect();
        let pairs = placeholders.len().min(arguments.len());
        for index in 0..pairs {
            let Some(expected) = arguments[index] else {
                break;
            };
            if placeholders[index].name.eq_ignore_ascii_case(expected) {
                continue;
            }
            let swapped = ((index + 1)..pairs).any(|later| {
                arguments[later].is_some_and(|value| {
                    placeholders[index].name.eq_ignore_ascii_case(value)
                        && placeholders[later].name.eq_ignore_ascii_case(expected)
                })
            });
            if swapped {
                let placeholder = placeholders[index];
                let start = literal.start_byte()
                    + literal_inner_offset(literal, source)
                    + placeholder.start;
                issues.push(issue(
                    language,
                    "S6673",
                    format!("Template placeholders should be in the right order: placeholder '{}' does not match with argument '{expected}'.", placeholder.name),
                    range_from_byte_offsets(start, start + placeholder.name.len(), source),
                ));
            }
            break;
        }
    }
    issues
}
