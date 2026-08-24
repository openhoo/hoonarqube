use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3052 — drop field initializers spelling the default value.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            Some((
                declarator,
                declarator_initializer(declarator, declarator.child_by_field_name("name")?),
            ))
        })
        .filter(|(_, initializer)| {
            initializer.is_some_and(|node| is_default_value_expression(node, source))
        })
        .map(|(declarator, _)| {
            issue(
                language,
                "S3052",
                "Remove this redundant initialization to the default value.",
                range_of(declarator),
            )
        })
        .collect()
}

/// csharpsquid:S3052 — fields initialized to their type's default value gain
/// nothing from the explicit assignment.
fn is_default_value_expression(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "null_literal" | "default_expression" => true,
        "boolean_literal" => node_text(node, source) == "false",
        "character_literal" => node_text(node, source) == "'\\0'",
        "integer_literal" => integer_literal_value(node_text(node, source)) == Some(0),
        "real_literal" => {
            let base = node_text(node, source).trim_end_matches(|c: char| c.is_ascii_alphabetic());
            base.bytes().all(|byte| byte == b'0' || byte == b'.')
                && base.bytes().any(|byte| byte == b'0')
        }
        _ => false,
    }
}
