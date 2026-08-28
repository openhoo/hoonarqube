use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{expression_name, first_named_child};
use hoonarqube_ir::Issue;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// csharpsquid:S5034 — a `ValueTask` may be consumed exactly once. Sonar
/// anchors the issue on the first consumption when later use makes it unsafe.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let value_task_locals: HashSet<&str> = collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| {
            declarator
                .parent()
                .and_then(|parent| parent.child_by_field_name("type"))
                .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "ValueTask")
        })
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();

    let mut consumptions: HashMap<&str, Vec<Node<'_>>> = HashMap::new();
    for await_expression in collect_kinds(root, &["await_expression"]) {
        if let Some(operand) = first_named_child(await_expression)
            && operand.kind() == "identifier"
        {
            let name = node_text(operand, source);
            if value_task_locals.contains(name) {
                consumptions.entry(name).or_default().push(operand);
            }
        }
    }
    for access in collect_kinds(root, &["member_access_expression"]) {
        if !matches!(
            expression_name(access, source),
            Some("Result" | "AsTask" | "GetAwaiter")
        ) {
            continue;
        }
        if let Some(base) = access.child_by_field_name("expression")
            && base.kind() == "identifier"
        {
            let name = node_text(base, source);
            if value_task_locals.contains(name) {
                consumptions.entry(name).or_default().push(base);
            }
        }
    }

    consumptions
        .into_values()
        .filter(|nodes| nodes.len() > 1)
        .filter_map(|nodes| nodes.first().copied())
        .map(|first| {
            issue(
                language,
                "S5034",
                "Refactor this 'ValueTask' usage to consume it only once.",
                range_of(first, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5034_anchors_first_of_repeated_consumptions() {
        let report = analyze_default(
            "class C\n{\n    async Task M()\n    {\n        ValueTask<int> pending = Load();\n        var first = await pending;\n        var second = await pending;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5034");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s5034_accepts_one_consumption() {
        let report = analyze_default(
            "class C\n{\n    async Task M()\n    {\n        ValueTask<int> pending = Load();\n        var value = await pending;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5034").is_empty());
    }
}
