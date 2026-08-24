use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2339 — public constants leak implementation details into
/// every referencing assembly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "const") && has_modifier(&modifiers, "public") {
            issues.push(issue(
                language,
                "S2339",
                "Make this constant private.",
                range_of(field),
            ));
        }
    }
    issues
}
