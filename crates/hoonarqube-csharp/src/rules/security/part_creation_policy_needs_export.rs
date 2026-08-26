use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::has_attribute;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4428 — `[PartCreationPolicy]` is meaningless without
/// '[Export]'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let attributes = attributes_of(type_node, source);
        if has_attribute(&attributes, "PartCreationPolicy") && !has_attribute(&attributes, "Export")
        {
            issues.push(issue(
                language,
                "S4428",
                "Add an '[Export]' attribute next to this '[PartCreationPolicy]'.",
                range_of(type_node, source),
            ));
        }
    }
    issues
}
