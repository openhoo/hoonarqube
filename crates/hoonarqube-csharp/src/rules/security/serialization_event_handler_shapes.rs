use super::support::return_type_text;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3927 — serialization callbacks return void and take exactly
/// one `StreamingContext`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const SERIALIZATION_EVENT_ATTRIBUTES: [&str; 4] = [
        "OnSerializing",
        "OnDeserializing",
        "OnSerialized",
        "OnDeserialized",
    ];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || !has_any_attribute(method, source, &SERIALIZATION_EVENT_ATTRIBUTES)
        {
            continue;
        }
        let parameters = parameters_of(method);
        let context_parameter = parameters
            .first()
            .and_then(|param| param.child_by_field_name("type"));
        let returns_void = return_type_text(method, source) == "void";
        let parameters_ok = parameters.len() == 1
            && context_parameter
                .is_some_and(|ty| simple_name(node_text(ty, source)) == "StreamingContext");
        let is_public = has_modifier(&modifiers_of(method, source), "public");
        if is_public || !returns_void || !parameters_ok {
            let action = match (is_public, returns_void, parameters_ok) {
                (true, true, false) => {
                    "non-public and have a single parameter of type 'StreamingContext'"
                }
                (false, true, false) => "have a single parameter of type 'StreamingContext'",
                (true, false, true) => "non-public and return 'void'",
                (false, false, true) => "return 'void'",
                (true, false, false) => {
                    "non-public, return 'void', and have a single parameter of type 'StreamingContext'"
                }
                (false, false, false) => {
                    "return 'void' and have a single parameter of type 'StreamingContext'"
                }
                (_, true, true) => continue,
            };
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S3927",
                format!("Make this method {action}."),
                range_of(name, source),
            ));
        }
    }
    issues
}
