use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3902 — `GetExecutingAssembly` couples code to its physical
/// assembly and breaks when moved.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Assembly", &["GetExecutingAssembly"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3902",
                "Remove this 'GetExecutingAssembly' call.",
                range_of(access),
            )
        })
        .collect()
}
