use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6668 — the exception belongs right after the message
/// template; passing it later drops it from structured output. Bound:
/// caught-variable names resolved within one body.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let caught = caught_exception_names(body, source);
        if caught.is_empty() {
            continue;
        }
        for call in collect_kinds(body, &["invocation_expression"]) {
            if !STRUCTURED_LOG_METHODS.contains(&callee_name(call, source).unwrap_or(""))
                || is_error_tainted(call)
            {
                continue;
            }
            let arguments = invocation_arguments(call);
            let template_index = arguments.iter().position(|argument| {
                first_named_child(*argument).is_some_and(|value| value.kind() == "string_literal")
            });
            let Some(template_index) = template_index else {
                continue;
            };
            let late_exception = arguments[template_index + 1..].iter().any(|argument| {
                collect_kinds(*argument, &["identifier"])
                    .into_iter()
                    .any(|identifier| caught.contains(node_text(identifier, source)))
            });
            if late_exception {
                issues.push(issue(
                    language,
                    "S6668",
                    "Pass the exception directly after the message template.",
                    range_of(call),
                ));
            }
        }
    }
    issues
}

/// ILogger-style logging methods taking `(level, exception, template…)`.
const STRUCTURED_LOG_METHODS: [&str; 7] = [
    "Log",
    "LogTrace",
    "LogDebug",
    "LogInformation",
    "LogWarning",
    "LogError",
    "LogCritical",
];

/// Names bound by catch clauses in the body.
fn caught_exception_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(body, &["catch_clause"])
        .into_iter()
        .filter_map(|clause| {
            collect_kinds(clause, &["catch_declaration"])
                .into_iter()
                .next()
        })
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_owned())
        .collect()
}
