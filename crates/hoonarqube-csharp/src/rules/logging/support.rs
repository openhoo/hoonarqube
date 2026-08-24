use crate::cst::{collect_kinds, is_error_tainted, node_text};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::{argument_expression, literal_inner_text};
use tree_sitter::Node;

/// `Microsoft.Extensions.Logging`-style structured-logging entry points
/// (`ILogger.Log*`, Serilog-style `Log.*`).
pub(crate) const LOG_METHOD_NAMES: [&str; 7] = [
    "Log",
    "LogTrace",
    "LogDebug",
    "LogInformation",
    "LogWarning",
    "LogError",
    "LogCritical",
];

/// csharpsquid:S6664 severity buckets with their tolerated call counts per
/// method body (debug=4, information=2, warning=1, error=1).
pub(crate) const LOG_LEVEL_LIMITS: [(&str, u32); 4] = [
    ("debug", 4),
    ("information", 2),
    ("warning", 1),
    ("error", 1),
];

/// Whether an invocation looks like structured logging through a logger
/// member (`logger.LogError(...)`, `Log.Information(...)`).
pub(crate) fn is_logging_call(invocation: Node<'_>, source: &str) -> bool {
    callee_name(invocation, source).is_some_and(|name| {
        LOG_METHOD_NAMES.contains(&name) && invocation_receiver(invocation).is_some()
    })
}

/// Logging invocations inside `scope`, in document order.
pub(crate) fn logging_calls<'t>(scope: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(scope, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call) && is_logging_call(*call, source))
        .collect()
}

/// A call's first plain string-literal argument, paired with the unquoted
/// inner text. Interpolated templates yield nothing here.
pub(crate) fn template_argument<'a>(
    call: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, &'a str)> {
    let first = invocation_arguments(call).into_iter().next()?;
    let expression = argument_expression(first);
    let literal = (expression.kind() == "string_literal").then_some(expression)?;
    Some((literal, literal_inner_text(literal, source)))
}

/// Placeholder names inside a message template, in textual order.
pub(crate) fn template_placeholders(template: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'{') {
        let open = index + offset + 1;
        match bytes[open..].iter().position(|byte| *byte == b'}') {
            Some(close) if close > 0 && !bytes[open..open + close].contains(&b'{') => {
                names.push(&template[open..open + close]);
                index = open + close + 1;
            }
            _ => break,
        }
    }
    names
}

/// Declarator names of a field or event declaration.
pub(crate) fn field_declarator_names<'a>(field: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(field, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}
