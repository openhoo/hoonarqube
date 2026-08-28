use super::support::bare_creations;
use super::support::creation_type_text;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3984 — exceptions built but never thrown.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in bare_creations(root) {
        if creation_type_text(creation, source).ends_with("Exception") {
            issues.push(issue(
                language,
                "S3984",
                "Throw this exception or remove this useless statement.",
                range_of(creation, source),
            ));
        }
    }
    issues
}
