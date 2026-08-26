use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3005 — `ThreadStatic` only affects static fields; on an
/// instance field it silently does nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            has_any_attribute(*field, source, &["ThreadStatic", "ThreadStaticAttribute"])
                && !has_modifier(&modifiers_of(*field, source), "static")
        })
        .filter_map(|field| {
            collect_kinds(field, &["variable_declarator"])
                .first()
                .copied()
        })
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3005",
                "Mark this field 'static'; '[ThreadStatic]' applies only to static fields.",
                range_of(name_node, source),
            )
        })
        .collect()
}
