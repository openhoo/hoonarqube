use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use crate::rules::structure::body_of;
use crate::rules::usage::mentions_identifier_outside_parameter_list;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6561 — timing measurements belong to `Stopwatch`, not wall
/// clock reads that jump with timezone or NTP changes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter_map(|method| body_of(method).map(|body| (method, body)))
        .filter(|(_, body)| mentions_identifier_outside_parameter_list(*body, "Stopwatch", source))
        .flat_map(|(_, body)| banned_member_accesses(body, source, "DateTime", &["Now", "Today"]))
        .map(|access| {
            issue(
                language,
                "S6561",
                "Measure elapsed time with 'Stopwatch' instead of 'DateTime.Now'.",
                range_of(access),
            )
        })
        .collect()
}
