use crate::cst::{collect_kinds, is_error_tainted, node_text};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::{argument_expression, is_string_literal, literal_inner_text};
use tree_sitter::Node;

/// `Microsoft.Extensions.Logging`-style structured-logging entry points
/// (`ILogger.Log*`, Serilog-style `Log.*`).
const LOG_METHOD_NAMES: [&str; 7] = [
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
fn is_logging_call(invocation: Node<'_>, source: &str) -> bool {
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

/// A call's first static string-literal argument, paired with the unquoted
/// inner text. Interpolated templates yield nothing here.
pub(crate) fn template_argument<'a>(
    call: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, &'a str)> {
    let first = invocation_arguments(call).into_iter().next()?;
    let expression = argument_expression(first);
    let literal = is_string_literal(expression).then_some(expression)?;
    Some((literal, literal_inner_text(literal, source)))
}

/// Placeholder names inside a message template, in textual order.
pub(crate) fn template_placeholders(template: &str) -> Vec<&str> {
    template_placeholder_spans(template)
        .into_iter()
        .map(|placeholder| placeholder.name)
        .collect()
}

/// Placeholder names and their byte offsets inside a message template.
pub(crate) fn template_placeholder_spans(template: &str) -> Vec<TemplatePlaceholder<'_>> {
    let mut placeholders = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'{') {
        let open = index + offset + 1;
        if bytes.get(open) == Some(&b'{') {
            // `{{` is an escaped brace, not a placeholder start; resume
            // after it instead of aborting the scan. A stray `}}` never
            // anchors this loop, which only ever seeks `{`.
            index = open + 1;
            continue;
        }
        match bytes[open..].iter().position(|byte| *byte == b'}') {
            Some(close) if close > 0 && !bytes[open..open + close].contains(&b'{') => {
                let raw = &template[open..open + close];
                let property = raw.split([',', ':']).next().unwrap_or(raw);
                let leading_space = property.len() - property.trim_start().len();
                let mut name = property.trim();
                let destructuring_prefix =
                    usize::from(name.starts_with('@') || name.starts_with('$'));
                name = name
                    .strip_prefix('@')
                    .or_else(|| name.strip_prefix('$'))
                    .unwrap_or(name);
                if !name.is_empty() {
                    placeholders.push(TemplatePlaceholder {
                        name,
                        start: open + leading_space + destructuring_prefix,
                    });
                }
                index = open + close + 1;
            }
            _ => break,
        }
    }
    placeholders
}

#[derive(Clone, Copy)]
pub(crate) struct TemplatePlaceholder<'a> {
    pub(crate) name: &'a str,
    pub(crate) start: usize,
}

/// Declarator names of a field or event declaration.
pub(crate) fn field_declarator_names<'a>(field: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(field, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{template_placeholder_spans, template_placeholders};

    #[test]
    fn template_placeholders_survives_escaped_braces_before_real_placeholder() {
        assert_eq!(template_placeholders("{A} and {B}"), vec!["A", "B"]);
        assert_eq!(template_placeholders("{{Name}} {OrderId}"), vec!["OrderId"]);
        assert_eq!(
            template_placeholders("{@User} {$OrderId} {Amount,10:C}"),
            vec!["User", "OrderId", "Amount"]
        );
        assert!(template_placeholders("{Unclosed {{x}}").is_empty());
        assert_eq!(
            template_placeholder_spans("{A} then {A}")
                .iter()
                .map(|placeholder| placeholder.start)
                .collect::<Vec<_>>(),
            vec![1, 10]
        );
    }
}
