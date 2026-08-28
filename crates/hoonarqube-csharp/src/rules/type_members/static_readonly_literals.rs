use super::support::is_literal_node;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::{accessibility_rank, has_modifier, type_declared_rank};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3962 — promote literal-backed static readonly fields to const.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            let mods = modifiers_of(*field, source);
            has_modifier(&mods, "static")
                && has_modifier(&mods, "readonly")
                && !(accessibility_rank(&mods) == 6
                    && enclosing_type(*field)
                        .is_some_and(|type_node| type_declared_rank(type_node, source) == 6))
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            is_literal_node(initializer).then_some((declarator, initializer))
        })
        .map(|(declarator, _)| {
            let name = declarator.child_by_field_name("name").unwrap_or(declarator);
            issue(
                language,
                "S3962",
                "Replace this 'static readonly' declaration with 'const'.",
                range_of(name, source),
            )
        })
        .collect()
}
