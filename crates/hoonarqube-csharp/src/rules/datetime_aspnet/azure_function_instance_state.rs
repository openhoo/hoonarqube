use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::expressions::{enclosing_type, expression_name, first_named_child};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6419 — Azure Function invocations must not mutate static
/// state shared by concurrent executions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let static_fields = mutable_static_fields(root, source);
    let mut issues = Vec::new();
    for method in azure_function_methods(root, source) {
        flag_assignments(method, &static_fields, source, language, &mut issues);
        flag_unary_updates(method, &static_fields, source, language, &mut issues);
    }
    issues
}

#[derive(Clone, Copy)]
struct StaticField<'source> {
    name: &'source str,
    owner_id: usize,
    owner_name: &'source str,
}

fn mutable_static_fields<'source>(
    root: Node<'_>,
    source: &'source str,
) -> Vec<StaticField<'source>> {
    let mut static_fields = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let Some(owner) = type_node.child_by_field_name("name") else {
            continue;
        };
        for field in member_declarations_of_kind(type_node, "field_declaration") {
            let modifiers = modifiers_of(field, source);
            if !has_modifier(&modifiers, "static")
                || has_modifier(&modifiers, "readonly")
                || has_modifier(&modifiers, "const")
            {
                continue;
            }
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    static_fields.push(StaticField {
                        name: node_text(name, source),
                        owner_id: type_node.id(),
                        owner_name: node_text(owner, source),
                    });
                }
            }
        }
    }
    static_fields
}

fn flag_assignments(
    method: Node<'_>,
    static_fields: &[StaticField<'_>],
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for assignment in collect_kinds(method, &["assignment_expression"]) {
        if let Some(target) = assignment.child_by_field_name("left")
            && is_static_field_target(target, method, static_fields, source)
        {
            issues.push(static_state_issue(target, source, language));
        }
    }
}

fn flag_unary_updates(
    method: Node<'_>,
    static_fields: &[StaticField<'_>],
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    for unary in collect_kinds(
        method,
        &["prefix_unary_expression", "postfix_unary_expression"],
    ) {
        if is_error_tainted(unary) {
            continue;
        }
        if let Some(target) = first_named_child(unary)
            && is_static_field_target(target, method, static_fields, source)
        {
            issues.push(static_state_issue(target, source, language));
        }
    }
}

fn is_static_field_target(
    target: Node<'_>,
    method: Node<'_>,
    static_fields: &[StaticField<'_>],
    source: &str,
) -> bool {
    let Some(name) = expression_name(target, source) else {
        return false;
    };
    if target.kind() == "member_access_expression" {
        let Some(receiver) = first_named_child(target) else {
            return false;
        };
        let receiver = simple_name(node_text(receiver, source));
        return static_fields
            .iter()
            .any(|field| field.name == name && field.owner_name == receiver);
    }

    let owner_id = enclosing_type(method).map(|owner| owner.id());
    owner_id.is_some_and(|owner_id| {
        static_fields
            .iter()
            .any(|field| field.name == name && field.owner_id == owner_id)
            && !local_or_parameter_named(method, name, source)
    })
}

fn local_or_parameter_named(method: Node<'_>, wanted: &str, source: &str) -> bool {
    parameters_of(method).iter().any(|parameter| {
        parameter
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == wanted)
    }) || collect_kinds(method, &["variable_declarator"])
        .into_iter()
        .any(|declarator| {
            declarator
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == wanted)
        })
}

fn static_state_issue(target: Node<'_>, source: &str, language: CsLanguage) -> Issue {
    issue(
        language,
        "S6419",
        "Do not modify a static state from Azure Function.",
        range_of(target, source),
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6419_does_not_confuse_unrelated_fields_with_locals() {
        let report = analyze_default(
            "class Other\n{\n    public static int hits;\n}\n\nclass Fn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        int hits = 0;\n        hits++;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6419").is_empty());
    }

    #[test]
    fn s6419_tracks_owned_and_explicitly_qualified_static_fields() {
        let report = analyze_default(
            "class Other\n{\n    public static int hits;\n}\n\nclass Fn\n{\n    private static int own;\n\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        own++;\n        Other.hits = 1;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6419").len(), 2);
    }
}
