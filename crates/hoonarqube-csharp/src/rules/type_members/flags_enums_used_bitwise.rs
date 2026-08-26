use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::naming::enum_has_flags_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4070 — '[Flags]' on enumerations nobody combines bitwise is
/// misleading decoration.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    if file_uses_bitwise_operators(root, source) {
        return Vec::new();
    }
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .filter_map(|enum_node| enum_node.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S4070",
                "Remove '[Flags]' from this enumeration or apply bitwise operations to it.",
                range_of(name, source),
            )
        })
        .collect()
}

/// Whether any binary or compound-assignment expression in the file applies
/// a bitwise operator (`&`, `|`, `^`, `|=`, `&=`, `^=`); `&&`/`||` stay
/// logical.
fn file_uses_bitwise_operators(root: Node<'_>, source: &str) -> bool {
    for expr in collect_kinds(root, &["binary_expression", "assignment_expression"]) {
        let bytes = node_text(expr, source).as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'|' | b'&' => {
                    let doubled = bytes.get(index + 1) == Some(&bytes[index]);
                    if !doubled {
                        return true;
                    }
                    index += 1;
                }
                b'^' => return true,
                _ => {}
            }
            index += 1;
        }
    }
    false
}
