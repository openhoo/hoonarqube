use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5042 — unbounded archive extraction grinds the host down
/// with zip bombs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EXTRACTION_METHODS: [&str; 2] = ["ExtractToDirectory", "ExtractToFile"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| EXTRACTION_METHODS.contains(&name))
        })
        .map(|invocation| {
            issue(
                language,
                "S5042",
                "Bound this archive extraction before running it.",
                range_of(invocation, source),
            )
        })
        .collect()
}
