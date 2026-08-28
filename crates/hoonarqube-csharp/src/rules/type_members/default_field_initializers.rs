use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_from_byte_offsets};
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
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            Some((name, initializer))
        })
        .filter(|(_, initializer)| is_default_value_expression(*initializer, source))
        .map(|(name, initializer)| {
            issue(
                language,
                "S3052",
                format!(
                    "Remove this initialization to '{}', the compiler will do that for you.",
                    node_text(name, source)
                ),
                range_from_byte_offsets(
                    source[name.end_byte()..initializer.start_byte()]
                        .find('=')
                        .map_or(initializer.start_byte(), |relative| {
                            name.end_byte() + relative
                        }),
                    initializer.end_byte(),
                    source,
                ),
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
