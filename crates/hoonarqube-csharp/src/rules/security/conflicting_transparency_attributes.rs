use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4211 — a safe-critical member inside a critical type has a
/// weaker transparency annotation than its container.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node)
            || !attributes_of(type_node, source).contains(&"SecurityCritical")
        {
            continue;
        }
        check_type_members(type_node, source, language, &mut issues);
    }
    issues
}

fn check_type_members(
    type_node: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for member in type_members(type_node) {
        let mut member_cursor = member.walk();
        for list in member
            .children(&mut member_cursor)
            .filter(|child| child.kind() == "attribute_list")
        {
            check_attribute_list(list, source, language, issues);
        }
    }
}

fn check_attribute_list(
    list: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for attribute in collect_kinds(list, &["attribute"]) {
        let Some(name) = attribute.child_by_field_name("name") else {
            continue;
        };
        if matches!(
            node_text(name, source),
            "SecuritySafeCritical" | "SecuritySafeCriticalAttribute"
        ) {
            issues.push(issue(
                language,
                "S4211",
                "Change or remove this attribute to be consistent with its container.",
                range_of(name, source),
            ));
        }
    }
}
