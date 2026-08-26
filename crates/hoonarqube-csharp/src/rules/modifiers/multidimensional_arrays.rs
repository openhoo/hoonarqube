use super::support::is_multidimensional_array;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3967 — multi-dimensional arrays should be jagged arrays.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for array_type_node in collect_kinds(root, &["array_type"]) {
        if is_multidimensional_array(array_type_node, source) {
            issues.push(issue(
                language,
                "S3967",
                "Use a jagged array instead of a multi-dimensional array.",
                range_of(array_type_node, source),
            ));
        }
    }
    issues
}
