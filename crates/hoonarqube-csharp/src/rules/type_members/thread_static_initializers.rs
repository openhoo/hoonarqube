use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2996 — `ThreadStatic` fields start uninitialized on every
/// thread; initializers run once and mislead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            has_any_attribute(*field, source, &["ThreadStatic", "ThreadStaticAttribute"])
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            Some((declarator, declarator_initializer(declarator, name)))
        })
        .filter(|(_, initializer)| initializer.is_some())
        .map(|(declarator, _)| {
            issue(
                language,
                "S2996",
                "Remove this initializer; '[ThreadStatic]' fields must not be initialized.",
                range_of(declarator),
            )
        })
        .collect()
}
