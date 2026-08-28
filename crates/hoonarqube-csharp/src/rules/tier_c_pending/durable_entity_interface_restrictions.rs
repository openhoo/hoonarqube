use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6424 — interfaces used with Durable Entity proxy/signal APIs
/// may contain methods only.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let interfaces = collect_kinds(root, &["interface_declaration"]);
    let mut issues = Vec::new();
    for generic in collect_kinds(root, &["generic_name"])
        .into_iter()
        .filter(|generic| !is_error_tainted(*generic))
    {
        let called = simple_name(node_text(generic, source));
        if !matches!(
            called,
            "SignalEntity" | "SignalEntityAsync" | "CreateEntityProxy"
        ) {
            continue;
        }
        let Some(type_argument) = collect_kinds(generic, &["type_argument_list"])
            .into_iter()
            .next()
            .and_then(|arguments| {
                let mut cursor = arguments.walk();
                arguments.children(&mut cursor).find(Node::is_named)
            })
        else {
            continue;
        };
        let interface_name = simple_name(node_text(type_argument, source));
        let Some(interface) = interfaces.iter().copied().find(|interface| {
            interface
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == interface_name)
        }) else {
            continue;
        };
        if let Some(property) = member_declarations_of_kind(interface, "property_declaration")
            .into_iter()
            .next()
            .and_then(|property| property.child_by_field_name("name"))
        {
            issues.push(issue(
                language,
                "S6424",
                format!(
                    "Use valid entity interface. {interface_name} contains property \"{}\". Only methods are allowed.",
                    node_text(property, source)
                ),
                range_of(generic, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6424_flags_properties_on_signaled_entity_interfaces() {
        let report = analyze_default(
            "interface ICartEntity\n{\n    int Count { get; }\n}\nclass C\n{\n    void M(IDurableEntityClient client)\n    {\n        client.SignalEntityAsync<ICartEntity>();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6424");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);
        assert!(flagged[0].message.contains("property \"Count\""));
    }

    #[test]
    fn s6424_accepts_method_only_signaled_entity_interfaces() {
        let report = analyze_default(
            "interface ICartEntity\n{\n    void Load();\n}\nclass C\n{\n    void M(IDurableEntityClient client)\n    {\n        client.SignalEntityAsync<ICartEntity>();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6424").is_empty());
    }
}
