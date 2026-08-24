use super::support::CALLABLE_BODY_OWNER_KINDS;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S108 — blocks are not left empty. Commented placeholder
/// bodies stay clean; callable bodies belong to S1186 and S3880.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        if is_error_tainted(block) {
            continue;
        }
        let owned_by_callable = block
            .parent()
            .is_some_and(|owner| CALLABLE_BODY_OWNER_KINDS.contains(&owner.kind()));
        let mut cursor = block.walk();
        let has_content = block.children(&mut cursor).any(|child| child.is_named());
        if !owned_by_callable && !has_content {
            issues.push(issue(
                language,
                "S108",
                "Either populate this block or remove it.",
                range_of(block),
            ));
        }
    }
    issues
}
