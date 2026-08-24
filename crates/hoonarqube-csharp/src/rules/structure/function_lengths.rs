use super::support::CALLABLE_BODY_OWNER_KINDS;
use super::support::body_of;
use super::support::name_anchor;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S138 — function bodies stay within the tolerated span.
pub(crate) fn check(root: Node<'_>, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let height = to_u32(body.end_position().row - body.start_position().row + 1);
        if height > options.maximum_function_lines {
            issues.push(issue(
                language,
                "S138",
                format!("Reduce this function's size; its body spans {height} lines."),
                range_of(name_anchor(function)),
            ));
        }
    }
    issues
}
