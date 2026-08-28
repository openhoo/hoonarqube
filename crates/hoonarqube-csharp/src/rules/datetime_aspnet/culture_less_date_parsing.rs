use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6580 — parsing dates without a format provider silently
/// adopts the machine's culture.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CULTURE_ARGUMENT_MARKERS: [&str; 2] = ["CultureInfo", "IFormatProvider"];
    const PARSING_TARGETS: [&str; 4] = ["Parse", "ParseExact", "TryParse", "ToDateTime"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(*invocation, source, None, &PARSING_TARGETS)
                || invocation_targets(*invocation, source, Some("DateTime"), &PARSING_TARGETS)
                || invocation_targets(*invocation, source, Some("Convert"), &PARSING_TARGETS)
        })
        .filter(|invocation| {
            !invocation_arguments(*invocation).iter().any(|argument| {
                let text = node_text(*argument, source);
                CULTURE_ARGUMENT_MARKERS
                    .iter()
                    .any(|marker| text.contains(marker))
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S6580",
                "Use a format provider when parsing date and time.",
                range_of(invocation, source),
            )
        })
        .collect()
}
