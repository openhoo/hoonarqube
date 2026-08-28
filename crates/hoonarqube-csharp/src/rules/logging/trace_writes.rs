use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6670 — `Trace` output bypasses sinks, levels, correlation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Trace", &["Write", "WriteLine"])
        .into_iter()
        .map(|access| {
            let anchor = access.child_by_field_name("name").unwrap_or(access);
            issue(
                language,
                "S6670",
                format!(
                    "Avoid using Trace.{}, use instead methods that specify the trace event type.",
                    node_text(anchor, source)
                ),
                range_of(anchor, source),
            )
        })
        .collect()
}
