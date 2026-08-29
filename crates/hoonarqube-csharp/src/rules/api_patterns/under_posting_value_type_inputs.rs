use crate::CsLanguage;
use crate::cst::{
    ancestors_of, attributes_of, collect_kinds, containing_namespace, is_error_tainted, issue,
    modifiers_of, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::type_members;
use crate::rules::structure::accessor_keyword;
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

const MESSAGE: &str = "Value type property used as input in a controller action should be nullable, required or annotated with the JsonRequiredAttribute to avoid under-posting.";

/// csharpsquid:S6964 — non-nullable value-type properties of bound action
/// models cannot distinguish omission from a supplied default value.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let models = declared_models(root, source);
    let input_model_ids = controller_input_models(root, source, &models);
    let custom_value_types: HashSet<&str> =
        collect_kinds(root, &["struct_declaration", "enum_declaration"])
            .into_iter()
            .filter_map(|declaration| declaration.child_by_field_name("name"))
            .map(|name| simple_name(node_text(name, source)))
            .collect();

    let mut issues = Vec::new();
    for model in models
        .into_iter()
        .filter(|model| input_model_ids.contains(&model.identity))
    {
        for property in type_members(model.node)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
            .filter(|property| is_bound_property(*property, source))
        {
            let Some(type_node) = property.child_by_field_name("type") else {
                continue;
            };
            let type_text = node_text(type_node, source);
            let value_type = is_value_type(type_text, &custom_value_types);
            let exempt = is_nullable(type_text)
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

struct Model<'t> {
    node: Node<'t>,
    name: String,
    namespace: String,
    identity: String,
}

fn declared_models<'t>(root: Node<'t>, source: &str) -> Vec<Model<'t>> {
    collect_kinds(root, &["class_declaration", "record_declaration"])
        .into_iter()
        .filter_map(|node| {
            let name_node = node.child_by_field_name("name")?;
            let name = canonical(simple_name(node_text(name_node, source))).to_owned();
            let namespace = containing_namespace(node, source);
            let identity = if namespace.is_empty() {
                name.clone()
            } else {
                format!("{namespace}.{name}")
            };
            Some(Model {
                node,
                name,
                namespace,
                identity,
            })
        })
        .collect()
}

fn controller_input_models(root: Node<'_>, source: &str, models: &[Model<'_>]) -> HashSet<String> {
    let mut inputs = HashSet::new();
    for controller in collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| has_any_attribute(*class_node, source, &["ApiController"]))
    {
        let controller_namespace = containing_namespace(controller, source);
        for method in type_members(controller)
            .into_iter()
            .filter(|member| is_controller_action(*member, source))
        {
            for parameter in parameters_of(method) {
                if attributes_of(parameter, source)
                    .iter()
                    .any(|name| matches!(*name, "FromServices" | "FromKeyedServices"))
                {
                    continue;
                }
                let Some(type_node) = parameter.child_by_field_name("type") else {
                    continue;
                };
                if let Some(identity) =
                    resolve_model_type(node_text(type_node, source), &controller_namespace, models)
                {
                    inputs.insert(identity);
                }
            }
        }
    }
    inputs
}

fn is_controller_action(method: Node<'_>, source: &str) -> bool {
    if method.kind() != "method_declaration" || is_error_tainted(method) {
        return false;
    }
    let modifiers = modifiers_of(method, source);
    has_modifier(&modifiers, "public")
        && !has_modifier(&modifiers, "static")
        && !has_any_attribute(method, source, &["NonAction"])
}

fn resolve_model_type(
    written: &str,
    controller_namespace: &str,
    models: &[Model<'_>],
) -> Option<String> {
    let normalized = normalize_type(written);
    if normalized.contains('<') || normalized.ends_with("[]") {
        return None;
    }
    let bare = normalized.trim_end_matches('?');
    let simple = simple_name(bare);
    let candidates: Vec<_> = models.iter().filter(|model| model.name == simple).collect();
    if bare.contains('.') {
        return candidates
            .into_iter()
            .find(|model| model.identity == bare)
            .map(|model| model.identity.clone());
    }
    let local: Vec<_> = candidates
        .iter()
        .filter(|model| model.namespace == controller_namespace)
        .collect();
    if local.len() == 1 {
        return Some(local[0].identity.clone());
    }
    (local.is_empty() && candidates.len() == 1).then(|| candidates[0].identity.clone())
}

fn normalize_type(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace() && *character != '@')
        .collect::<String>()
        .replace("global::", "")
}

fn canonical(name: &str) -> &str {
    name.strip_prefix('@').unwrap_or(name)
}

fn is_nullable(type_text: &str) -> bool {
    let normalized = normalize_type(type_text);
    normalized.ends_with('?')
        || normalized.starts_with("Nullable<")
        || normalized.starts_with("System.Nullable<")
}

fn is_value_type(type_text: &str, custom: &HashSet<&str>) -> bool {
    let normalized = normalize_type(type_text);
    let name = simple_name(normalized.trim_end_matches('?'));
    matches!(
        name,
        "sbyte"
            | "byte"
            | "short"
            | "ushort"
            | "int"
            | "uint"
            | "long"
            | "ulong"
            | "nint"
            | "nuint"
            | "char"
            | "bool"
            | "decimal"
            | "double"
            | "float"
            | "Guid"
            | "DateOnly"
            | "TimeOnly"
            | "DateTime"
            | "DateTimeOffset"
            | "TimeSpan"
    ) || custom.contains(name)
}

fn is_bound_property(property: Node<'_>, source: &str) -> bool {
    let modifiers = modifiers_of(property, source);
    if !has_modifier(&modifiers, "public")
        || has_modifier(&modifiers, "static")
        || has_any_attribute(property, source, &["JsonIgnore"])
    {
        return false;
    }
    let included = has_any_attribute(property, source, &["JsonInclude"]);
    collect_kinds(property, &["accessor_declaration"])
        .into_iter()
        .filter(|accessor| {
            ancestors_of(*accessor)
                .find(|ancestor| ancestor.kind() == "property_declaration")
                .is_some_and(|owner| owner.id() == property.id())
        })
        .any(|accessor| {
            matches!(accessor_keyword(accessor, source), "set" | "init")
                && (included || !has_modifier(&modifiers_of(accessor, source), "private"))
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6964_only_uses_real_controller_action_inputs() {
        let report = analyze_default(
            "class Model { public int Count { get; set; } }\n[ApiController] class C {\n[NonAction] public void Helper(Model model) { }\npublic static void Static(Model model) { }\npublic void Injected([FromServices] Model model) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6964").is_empty());
    }

    #[test]
    fn s6964_respects_namespaces_and_serializable_properties() {
        let report = analyze_default(
            "namespace One { class Model { public int Count { get; set; } } }\nnamespace Two { class Model { public int Hidden { get; } [JsonIgnore] public int Ignored { get; set; } public required int Required { get; init; } public DateOnly Date { get; init; } } [ApiController] class C { public void Save(Model model) { } } }\n",
        );
        let found = with_key(&report, "csharpsquid:S6964");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, super::MESSAGE);
    }
}
