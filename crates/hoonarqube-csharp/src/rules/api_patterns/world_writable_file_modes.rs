use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::expression_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2612 — files writable or executable by group/others
/// invite tampering. Bound: spelled `UnixFileMode.<Member>` values;
/// raw octal modes stay out of scope.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|access| !is_error_tainted(*access))
        .filter(|access| {
            access
                .child_by_field_name("expression")
                .is_some_and(|qualifier| node_text(qualifier, source) == "UnixFileMode")
        })
        .filter(|access| {
            WORLD_WRITABLE_MODE_MEMBERS.contains(&expression_name(*access, source).unwrap_or(""))
        })
        .map(|access| {
            issue(
                language,
                "S2612",
                "This file mode grants access beyond the owner; restrict it.",
                range_of(access),
            )
        })
        .collect()
}

/// File-mode members granting access beyond the owner.
const WORLD_WRITABLE_MODE_MEMBERS: [&str; 3] = ["OthersWrite", "OthersExecute", "GroupWrite"];
