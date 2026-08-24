use super::support::is_literal_node;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3962 — promote literal-backed static readonly fields to const.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            let mods = modifiers_of(*field, source);
            has_modifier(&mods, "static") && has_modifier(&mods, "readonly")
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            is_literal_node(initializer).then_some((declarator, initializer))
        })
        .map(|(declarator, _)| {
            issue(
                language,
                "S3962",
                "Declare this field as 'const' instead of 'static readonly'.",
                range_of(declarator),
            )
        })
        .collect()
}
