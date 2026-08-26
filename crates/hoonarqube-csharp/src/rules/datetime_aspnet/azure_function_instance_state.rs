use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6419 — mutable instance state leaks across parallel Azure
/// Function invocations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let hosts_function = member_declarations_of_kind(type_node, "method_declaration")
            .iter()
            .any(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]));
        if !hosts_function {
            continue;
        }
        for field in member_declarations_of_kind(type_node, "field_declaration") {
            if is_error_tainted(field) {
                continue;
            }
            let modifiers = modifiers_of(field, source);
            let immutable = has_modifier(&modifiers, "static")
                || has_modifier(&modifiers, "readonly")
                || has_modifier(&modifiers, "const");
            if !immutable {
                issues.push(issue(
                    language,
                    "S6419",
                    "Keep this class stateless; do not hold mutable instance fields.",
                    range_of(field, source),
                ));
            }
        }
    }
    issues
}
