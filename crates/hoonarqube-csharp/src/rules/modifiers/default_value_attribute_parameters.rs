use super::support::has_attribute;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3451 — on parameters, `[DefaultValue]` silently behaves like
/// `[DefaultParameterValue]`; spell the intent out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        if has_attribute(&attributes_of(parameter, source), "DefaultValue") {
            issues.push(issue(
                language,
                "S3451",
                "Use '[DefaultParameterValue]' instead of '[DefaultValue]'.",
                range_of(parameter, source),
            ));
        }
    }
    issues
}
