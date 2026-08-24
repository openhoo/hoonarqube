use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S109 — numbers beyond -1/0/1 deserve names.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| {
            !magic_number_exempt(*literal, source)
                && !is_small_allowed_number(node_text(*literal, source))
        })
        .map(|literal| {
            issue(
                language,
                "S109",
                "Replace this magic number with a named constant.",
                range_of(literal),
            )
        })
        .collect()
}

/// Whether a numeric literal's value is exactly -1, 0, or 1.
fn is_small_allowed_number(text: &str) -> bool {
    if let Some(value) = integer_literal_value(text) {
        return value <= 1;
    }
    // Real literals: spell out zero and one textually to stay exact.
    let base = text.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let Some((integer, fraction)) = base.split_once('.') else {
        return false;
    };
    let normalized = integer.trim_start_matches('0');
    let fraction_all_zero = fraction.bytes().all(|digit| digit == b'0');
    (normalized.is_empty() && fraction_all_zero)
        || (normalized == "1" && (fraction.is_empty() || fraction_all_zero))
}

/// Contexts where even large numbers are not magic: enumeration members,
/// constant declarations, and parameter defaults.
fn magic_number_exempt(mut literal: Node<'_>, source: &str) -> bool {
    while let Some(parent) = literal.parent() {
        match parent.kind() {
            "enum_member_declaration" | "parameter" => return true,
            "field_declaration" | "local_declaration_statement" => {
                return has_modifier(&modifiers_of(parent, source), "const");
            }
            _ => {}
        }
        literal = parent;
    }
    false
}
