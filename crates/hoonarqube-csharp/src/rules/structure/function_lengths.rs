use super::support::CALLABLE_BODY_OWNER_KINDS;
use super::support::body_of;
use super::support::name_anchor;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S138 — function bodies stay within the tolerated span.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let height =
            to_u32(body.end_position().row - body.start_position().row + 1).saturating_sub(2);
        if height > options.maximum_function_lines {
            let name = node_text(name_anchor(function), source);
            issues.push(issue(
                language,
                "S138",
                format!(
                    "This method '{name}' has {height} lines, which is greater than the {} lines authorized. Split it into smaller methods.",
                    options.maximum_function_lines
                ),
                range_of(name_anchor(function), source),
            ));
        }
    }
    issues
}
