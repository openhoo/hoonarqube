use crate::CsLanguage;
use crate::cst::{
    attributes_of, collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const MESSAGE: &str = "Value type property used as input in a controller action should be nullable, required or annotated with the JsonRequiredAttribute to avoid under-posting.";

/// csharpsquid:S6964 — non-nullable value-type properties of bound action
/// models cannot distinguish omission from a supplied default value.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let input_models: std::collections::HashSet<&str> = collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| has_any_attribute(*class_node, source, &["ApiController"]))
        .flat_map(|class_node| type_members(class_node))
        .filter(|member| member.kind() == "method_declaration")
        .flat_map(parameters_of)
        .filter_map(|parameter| parameter.child_by_field_name("type"))
        .map(|ty| simple_name(node_text(ty, source)))
        .collect();

    let mut issues = Vec::new();
    for model in collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| {
            class_node
                .child_by_field_name("name")
                .is_some_and(|name| input_models.contains(node_text(name, source)))
        })
    {
        for property in type_members(model)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
        {
            let Some(type_node) = property.child_by_field_name("type") else {
                continue;
            };
            let type_text = node_text(type_node, source);
            let value_type = matches!(
                simple_name(type_text),
                "int"
                    | "long"
                    | "short"
                    | "byte"
                    | "bool"
                    | "decimal"
                    | "double"
                    | "float"
                    | "Guid"
                    | "DateTime"
            );
            let exempt = type_text.contains('?')
                || has_modifier(&modifiers_of(property, source), "required")
                || attributes_of(property, source)
                    .iter()
                    .any(|name| matches!(*name, "JsonRequired" | "RequiredMember"));
            if value_type && !exempt {
                let anchor = property.child_by_field_name("name").unwrap_or(property);
                issues.push(issue(language, "S6964", MESSAGE, range_of(anchor, source)));
            }
        }
    }
    issues
}
