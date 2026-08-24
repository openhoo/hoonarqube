use super::support::bare_creations;
use super::support::creation_type_text;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1848 — objects created straight into thin air. Exception
/// instantiations belong to S3984 instead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in bare_creations(root) {
        if !creation_type_text(creation, source).ends_with("Exception") {
            issues.push(issue(
                language,
                "S1848",
                "Either use this created object or remove the instantiation.",
                range_of(creation),
            ));
        }
    }
    issues
}
