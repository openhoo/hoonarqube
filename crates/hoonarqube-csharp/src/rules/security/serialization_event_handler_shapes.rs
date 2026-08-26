use super::support::return_type_text;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::modifiers::has_any_attribute;
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
        let shape_ok = return_type_text(method, source) == "void"
            && parameters.len() == 1
            && context_parameter
                .is_some_and(|ty| simple_name(node_text(ty, source)) == "StreamingContext");
        if !shape_ok {
            issues.push(issue(
                language,
                "S3927",
                "Serialization callbacks return void and take exactly one 'StreamingContext'.",
                range_of(method, source),
            ));
        }
    }
    issues
}
