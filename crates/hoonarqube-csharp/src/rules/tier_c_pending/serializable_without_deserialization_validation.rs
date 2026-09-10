use crate::CsLanguage;
use crate::cst::{
    canonical_identifier, collect_kinds, direct_attributes, is_error_tainted, issue, node_text,
    parameters_of, range_of,
};
use crate::rules::expressions::{binary_operands, first_named_child, operator_of};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const MESSAGE: &str = "Validate data in this deserialization constructor.";

/// csharpsquid:S5766 — mirror the owning analyzer's conditional-validation
/// contract for serializable constructors and deserialization callbacks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class) || !class_has_serializable_attribute(class, source) {
            continue;
        }
        issues.extend(serializable_class_issues(class, source, language));
    }
    issues
}

fn serializable_class_issues(class: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let members = type_members(class);
    let constructors: Vec<Node<'_>> = members
        .iter()
        .copied()
        .filter(|member| member.kind() == "constructor_declaration")
        .collect();
    if !constructors
        .iter()
        .any(|constructor| !parameters_of(*constructor).is_empty())
    {
        return Vec::new();
    }

    let constructor_conditions = collect_constructor_conditions(&constructors, source);
    let implements_iserializable = class_implements(
        class,
        source,
        &[
            "ISerializable",
            "System.Runtime.Serialization.ISerializable",
            "global::System.Runtime.Serialization.ISerializable",
        ],
    );
    let implements_deserialization_callback = class_implements(
        class,
        source,
        &[
            "IDeserializationCallback",
            "System.Runtime.Serialization.IDeserializationCallback",
            "global::System.Runtime.Serialization.IDeserializationCallback",
        ],
    );

    let mut issues = Vec::new();
    if !implements_iserializable && !implements_deserialization_callback {
        push_all_constructor_issues(&mut issues, language, &constructor_conditions, source);
    }
    if implements_iserializable && !has_valid_deserialization_constructor(&constructor_conditions) {
        push_ordinary_constructor_issues(&mut issues, language, &constructor_conditions, source);
    }
    if implements_deserialization_callback && !on_deserialization_has_conditions(class, source) {
        push_all_constructor_issues(&mut issues, language, &constructor_conditions, source);
    }
    issues
}

fn collect_constructor_conditions<'a>(
    constructors: &[Node<'a>],
    source: &str,
) -> Vec<(Node<'a>, bool, bool)> {
    constructors
        .iter()
        .copied()
        .map(|constructor| {
            let is_deserialization = has_serialization_parameters(constructor, source);
            let has_conditions = if is_deserialization {
                contains_conditional_constructs(constructor, source)
            } else {
                has_parameters_used_in_conditional_constructs(constructor, source)
            };
            (constructor, is_deserialization, has_conditions)
        })
        .collect()
}

fn has_valid_deserialization_constructor(conditions: &[(Node<'_>, bool, bool)]) -> bool {
    conditions
        .iter()
        .any(|(_, is_deserialization, has_conditions)| *is_deserialization && *has_conditions)
}

fn push_all_constructor_issues(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    conditions: &[(Node<'_>, bool, bool)],
    source: &str,
) {
    for (constructor, _, has_conditions) in conditions.iter().copied() {
        if has_conditions {
            push_constructor_issue(issues, language, constructor, source);
        }
    }
}

fn push_ordinary_constructor_issues(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    conditions: &[(Node<'_>, bool, bool)],
    source: &str,
) {
    for (constructor, is_deserialization, has_conditions) in conditions.iter().copied() {
        if !is_deserialization && has_conditions {
            push_constructor_issue(issues, language, constructor, source);
        }
    }
}
fn class_has_serializable_attribute(class: Node<'_>, source: &str) -> bool {
    direct_attributes(class).into_iter().any(|attribute| {
        let Some(name) = attribute.child_by_field_name("name") else {
            return false;
        };
        matches!(
            node_text(name, source).trim(),
            "Serializable"
                | "SerializableAttribute"
                | "System.Serializable"
                | "System.SerializableAttribute"
                | "global::System.Serializable"
                | "global::System.SerializableAttribute"
        )
    })
}

fn class_implements(class: Node<'_>, source: &str, expected: &[&str]) -> bool {
    let mut class_cursor = class.walk();
    class
        .children(&mut class_cursor)
        .filter(|child| child.kind() == "base_list")
        .any(|base_list| {
            let mut base_cursor = base_list.walk();
            base_list
                .named_children(&mut base_cursor)
                .any(|base| expected.contains(&node_text(base, source).trim()))
        })
}

fn push_constructor_issue(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    constructor: Node<'_>,
    source: &str,
) {
    let Some(name) = constructor.child_by_field_name("name") else {
        return;
    };
    issues.push(issue(language, "S5766", MESSAGE, range_of(name, source)));
}

fn has_serialization_parameters(declaration: Node<'_>, source: &str) -> bool {
    if declaration.kind() != "constructor_declaration" {
        return false;
    }
    let parameters = parameters_of(declaration);
    parameters.len() == 2
        && parameters[0]
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                matches!(
                    node_text(type_node, source).trim(),
                    "SerializationInfo"
                        | "System.Runtime.Serialization.SerializationInfo"
                        | "global::System.Runtime.Serialization.SerializationInfo"
                )
            })
        && parameters[1]
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                matches!(
                    node_text(type_node, source).trim(),
                    "StreamingContext"
                        | "System.Runtime.Serialization.StreamingContext"
                        | "global::System.Runtime.Serialization.StreamingContext"
                )
            })
}

fn contains_conditional_constructs(root: Node<'_>, source: &str) -> bool {
    !collect_kinds(
        root,
        &[
            "if_statement",
            "conditional_expression",
            "switch_statement",
            "switch_expression",
        ],
    )
    .is_empty()
        || collect_kinds(root, &["binary_expression"])
            .into_iter()
            .any(|expression| operator_of(expression) == Some("??"))
        || collect_kinds(root, &["assignment_expression"])
            .into_iter()
            .any(|expression| has_operator(expression, source, "??="))
}

fn has_parameters_used_in_conditional_constructs(constructor: Node<'_>, source: &str) -> bool {
    let parameter_names: Vec<&str> = parameters_of(constructor)
        .into_iter()
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| canonical_identifier(node_text(name, source)))
        .collect();
    if parameter_names.is_empty() {
        return false;
    }
    conditional_inputs(constructor, source)
        .into_iter()
        .any(|input| references_parameter(input, &parameter_names, source))
}

fn conditional_inputs<'a>(root: Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut inputs = Vec::new();
    add_conditional_construct_inputs(root, &mut inputs);
    add_coalescing_inputs(root, source, &mut inputs);
    add_switch_expression_inputs(root, &mut inputs);
    inputs
}

fn add_conditional_construct_inputs<'a>(root: Node<'a>, inputs: &mut Vec<Node<'a>>) {
    for conditional in collect_kinds(
        root,
        &["if_statement", "conditional_expression", "switch_statement"],
    ) {
        let field = if conditional.kind() == "switch_statement" {
            "value"
        } else {
            "condition"
        };
        if let Some(input) = conditional.child_by_field_name(field) {
            inputs.push(input);
        }
    }
}

fn add_coalescing_inputs<'a>(root: Node<'a>, source: &str, inputs: &mut Vec<Node<'a>>) {
    for expression in collect_kinds(root, &["binary_expression"]) {
        if operator_of(expression) == Some("??")
            && let Some((left, _)) = binary_operands(expression)
        {
            inputs.push(left);
        }
    }
    for expression in collect_kinds(root, &["assignment_expression"]) {
        if has_operator(expression, source, "??=")
            && let Some(left) = expression.child_by_field_name("left")
        {
            inputs.push(left);
        }
    }
}

fn add_switch_expression_inputs<'a>(root: Node<'a>, inputs: &mut Vec<Node<'a>>) {
    for switch in collect_kinds(root, &["switch_expression"]) {
        if let Some(expression) = first_named_child(switch) {
            inputs.push(expression);
        }
        for arm in collect_kinds(switch, &["switch_expression_arm"]) {
            let named = named_children(arm);
            if let Some(pattern) = named.first() {
                inputs.push(*pattern);
            }
            if let Some(when_clause) = named.get(1)
                && when_clause.kind() == "when_clause"
                && let Some(condition) = first_named_child(*when_clause)
            {
                inputs.push(condition);
            }
        }
    }
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn references_parameter(expression: Node<'_>, names: &[&str], source: &str) -> bool {
    collect_kinds(expression, &["identifier"])
        .into_iter()
        .any(|identifier| {
            let name = canonical_identifier(node_text(identifier, source));
            names.contains(&name)
        })
}

fn has_operator(expression: Node<'_>, source: &str, expected: &str) -> bool {
    expression
        .child_by_field_name("operator")
        .is_some_and(|operator| node_text(operator, source) == expected)
}

fn on_deserialization_has_conditions(class: Node<'_>, source: &str) -> bool {
    type_members(class).into_iter().any(|member| {
        member.kind() == "method_declaration"
            && is_on_deserialization(member, source)
            && contains_conditional_constructs(member, source)
    })
}

fn is_on_deserialization(method: Node<'_>, source: &str) -> bool {
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    if node_text(name, source) != "OnDeserialization" {
        return false;
    }
    let parameters = parameters_of(method);
    parameters.len() == 1
        && parameters
            .first()
            .and_then(|parameter| parameter.child_by_field_name("type"))
            .is_some_and(|type_node| {
                matches!(
                    node_text(type_node, source).trim().trim_end_matches('?'),
                    "object" | "System.Object" | "global::System.Object"
                )
            })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5766_flags_the_ordinary_constructor_when_its_parameter_is_unvalidated() {
        let report = analyze_default(
            "using System;\nusing System.Runtime.Serialization;\n\n[Serializable]\npublic sealed class InternalUrl : ISerializable\n{\n    private string url = string.Empty;\n\n    public InternalUrl(string candidate)\n    {\n        if (!candidate.StartsWith(\"http://localhost/\", StringComparison.Ordinal))\n        {\n            url = \"http://localhost/default\";\n        }\n        else\n        {\n            url = candidate;\n        }\n    }\n\n    protected InternalUrl(SerializationInfo info, StreamingContext context)\n    {\n        url = info.GetString(\"url\")!;\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S5766");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Validate data in this deserialization constructor."
        );
        assert_eq!(found[0].range.start.line, 9);
        assert_eq!(found[0].range.start.column, 11);
    }

    #[test]
    fn s5766_accepts_a_serialization_constructor_with_conditional_validation() {
        let report = analyze_default(
            "using System;\nusing System.Runtime.Serialization;\n\n[Serializable]\npublic sealed class InternalUrl : ISerializable\n{\n    private string url = string.Empty;\n\n    public InternalUrl(string candidate)\n        => url = Normalize(candidate);\n\n    protected InternalUrl(SerializationInfo info, StreamingContext context)\n        => url = Normalize(info.GetString(\"url\") ?? string.Empty);\n\n    private static string Normalize(string candidate)\n        => candidate.StartsWith(\"http://localhost/\", StringComparison.Ordinal)\n            ? candidate\n            : \"http://localhost/default\";\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }

    #[test]
    fn s5766_requires_the_callback_body_to_contain_validation_conditions() {
        let report = analyze_default(
            "using System;\nusing System.Runtime.Serialization;\n\n[Serializable]\npublic sealed class InternalUrlAlias : ISerializable, IDeserializationCallback\n{\n    private string url = string.Empty;\n\n    public InternalUrlAlias(string candidate)\n        => url = NormalizeUrl(candidate);\n\n    protected InternalUrlAlias(SerializationInfo info, StreamingContext context)\n        => url = info.GetString(\"url\") ?? string.Empty;\n\n    public void OnDeserialization(object? sender)\n        => url = url;\n\n    void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)\n        => info.AddValue(\"url\", url);\n\n    private static string NormalizeUrl(string candidate)\n        => candidate.StartsWith(\"http://localhost/\", StringComparison.Ordinal)\n            ? candidate\n            : \"http://localhost/default\";\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S5766");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 12);
        assert_eq!(found[0].range.start.column, 14);
    }

    #[test]
    fn s5766_accepts_a_callback_with_inline_conditions() {
        let report = analyze_default(
            "using System;\nusing System.Runtime.Serialization;\n\n[Serializable]\npublic sealed class CallbackSafe : IDeserializationCallback\n{\n    private string url = string.Empty;\n\n    public CallbackSafe(string candidate)\n    {\n        if (!candidate.StartsWith(\"http://localhost/\", StringComparison.Ordinal))\n        {\n            url = \"http://localhost/default\";\n        }\n        else\n        {\n            url = candidate;\n        }\n    }\n\n    public void OnDeserialization(object sender)\n    {\n        if (!url.StartsWith(\"http://localhost/\", StringComparison.Ordinal))\n        {\n            url = \"http://localhost/default\";\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }

    #[test]
    fn s5766_ignores_serializable_types_without_parameterized_constructors() {
        let report = analyze_default(
            "[Serializable]\nclass First\n{\n}\n[SerializableAttribute]\nclass Second\n{\n    public Second() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }

    #[test]
    fn s5766_accepts_the_long_serializable_attribute_spelling() {
        let report = analyze_default(
            "[SerializableAttribute]\nclass Session\n{\n    public Session(string value) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }

    #[test]
    fn s5766_unrelated_method_attributes_do_not_satisfy_constructor_validation() {
        let report = analyze_default(
            "[Serializable]\nclass Session\n{\n    public Session(string candidate)\n    {\n        if (candidate == string.Empty)\n        {\n        }\n    }\n\n    [Obsolete]\n    void Refresh()\n    {\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S5766");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s5766_classes_without_the_attribute_stay_clean() {
        let report = analyze_default("class Session\n{\n    public Session(string value) { }\n}\n");
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }
}
