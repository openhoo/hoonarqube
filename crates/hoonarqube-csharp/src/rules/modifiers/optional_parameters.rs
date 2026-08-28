use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, issue, modifiers_of, parameters_of, range_from_byte_offsets, range_of,
};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use crate::rules::naming::has_explicit_interface_specifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2360 — optional parameters complicate overload resolution;
/// overrides and explicit implementations must repeat base defaults, so they
/// stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override")
            || has_explicit_interface_specifier(method)
            || !has_modifier(&modifiers, "public")
            || enclosing_type(method)
                .is_none_or(|type_node| type_declared_rank(type_node, source) != 6)
        {
            continue;
        }
        for parameter in parameters_of(method) {
            let mut cursor = parameter.walk();
            let equals = parameter
                .children(&mut cursor)
                .find(|child| child.kind() == "=");
            if let Some(equals) = equals {
                let mut named_cursor = parameter.walk();
                let default_value = parameter.named_children(&mut named_cursor).last();
                let range = default_value.map_or_else(
                    || range_of(equals, source),
                    |value| range_from_byte_offsets(equals.start_byte(), value.end_byte(), source),
                );
                issues.push(issue(
                    language,
                    "S2360",
                    "Use the overloading mechanism instead of the optional parameters.",
                    range,
                ));
            }
        }
    }
    issues
}
