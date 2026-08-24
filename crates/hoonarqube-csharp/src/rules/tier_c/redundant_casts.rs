use super::support::FLOATING_TYPES;
use super::support::INTEGER_TYPES;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1905 — casts of literals to their own obvious type. Subset:
/// predefined-type targets over scalar literals; user-defined conversions,
/// nullable targets, and casts of computed expressions stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["cast_expression"])
        .into_iter()
        .filter(|cast| !is_error_tainted(*cast))
        .filter_map(|cast| {
            let type_node = cast.child_by_field_name("type")?;
            let value = cast.child_by_field_name("value")?;
            let type_text = node_text(type_node, source);
            if type_text.contains('?') {
                return None;
            }
            let target = simple_name(type_text);
            let redundant = match value.kind() {
                "integer_literal" => INTEGER_TYPES.contains(&target),
                "real_literal" => FLOATING_TYPES.contains(&target),
                "string_literal" => target == "string",
                "character_literal" => target == "char",
                "boolean_literal" => target == "bool",
                _ => false,
            };
            redundant.then_some(cast)
        })
        .map(|cast| {
            issue(
                language,
                "S1905",
                "Remove this redundant cast.",
                range_of(cast),
            )
        })
        .collect()
}
