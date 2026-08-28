use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{expression_name, invocation_arguments, invocation_targets};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6675 — gating `WriteLineIf` with a `TraceSwitch` level hides
/// the decision from the configuration system.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_targets(*call, source, Some("Trace"), &["WriteLineIf"]))
        .filter(|call| {
            invocation_arguments(*call).first().is_some_and(|argument| {
                let expression = argument_expression(*argument);
                TRACE_SWITCH_LEVELS.contains(&expression_name(expression, source).unwrap_or(""))
            })
        })
        .map(|call| {
            let anchor = invocation_arguments(call)
                .first()
                .map_or(call, |argument| argument_expression(*argument));
            issue(
                language,
                "S6675",
                "'Trace.WriteLineIf' should not be used with 'TraceSwitch' levels.",
                range_of(anchor, source),
            )
        })
        .collect()
}

/// `TraceSwitch` level properties that should not gate conditional traces.
const TRACE_SWITCH_LEVELS: [&str; 4] = ["TraceError", "TraceWarning", "TraceInfo", "TraceVerbose"];
