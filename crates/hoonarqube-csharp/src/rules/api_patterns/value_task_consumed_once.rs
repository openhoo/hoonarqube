use super::support::collect_kinds_in_callable;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, simple_name};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{expression_name, first_named_child};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S5034 — a `ValueTask` may be consumed exactly once. Sonar
/// anchors the issue on the first consumption when later use makes it unsafe.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        issues.extend(check_body(body, source, language));
    }
    issues
}

fn check_body(body: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declaration_counts = value_task_declaration_counts(body, source);
    let consumptions = value_task_consumptions(body, source, &declaration_counts);
    repeated_first_consumptions(consumptions)
        .into_iter()
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

fn value_task_declaration_counts<'a>(body: Node<'_>, source: &'a str) -> HashMap<&'a str, usize> {
    let mut declaration_counts = HashMap::new();
    for declarator in collect_kinds_in_callable(body, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| is_value_task_declarator(*declarator, source))
    {
        if let Some(name) = declarator.child_by_field_name("name") {
            *declaration_counts
                .entry(node_text(name, source))
                .or_default() += 1;
        }
    }
    declaration_counts
}

fn is_value_task_declarator(declarator: Node<'_>, source: &str) -> bool {
    declarator
        .parent()
        .and_then(|parent| parent.child_by_field_name("type"))
        .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "ValueTask")
}

fn value_task_consumptions<'tree, 'source>(
    body: Node<'tree>,
    source: &'source str,
    declaration_counts: &HashMap<&'source str, usize>,
) -> HashMap<&'source str, Vec<Node<'tree>>> {
    let mut consumptions: HashMap<&str, Vec<Node<'_>>> = HashMap::new();
    for node in collect_kinds_in_callable(body, &["await_expression", "member_access_expression"]) {
        let Some(identifier) = consumed_identifier(node, source) else {
            continue;
        };
        let name = node_text(identifier, source);
        if declaration_counts.get(name) == Some(&1) {
            consumptions.entry(name).or_default().push(identifier);
        }
    }
    consumptions
}

fn consumed_identifier<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if node.kind() == "await_expression" {
        return first_named_child(node).filter(|operand| operand.kind() == "identifier");
    }
    if node.kind() != "member_access_expression"
        || !matches!(
            expression_name(node, source),
            Some("Result" | "AsTask" | "GetAwaiter")
        )
    {
        return None;
    }
    node.child_by_field_name("expression")
        .filter(|base| base.kind() == "identifier")
}

fn repeated_first_consumptions<'tree>(
    consumptions: HashMap<&str, Vec<Node<'tree>>>,
) -> Vec<Node<'tree>> {
    let mut first_consumptions: Vec<Node<'_>> = consumptions
        .into_values()
        .filter(|nodes| nodes.len() > 1)
        .filter_map(|nodes| nodes.first().copied())
        .collect();
    first_consumptions.sort_unstable_by_key(tree_sitter::Node::start_byte);
    first_consumptions
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

    #[test]
    fn s5034_keeps_same_named_locals_in_separate_callables() {
        let report = analyze_default(
            "class C\n{\n    async Task First()\n    {\n        ValueTask<int> pending = Load();\n        var value = await pending;\n    }\n\n    async Task Second()\n    {\n        ValueTask<int> pending = Load();\n        var value = await pending;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5034").is_empty());
    }

    #[test]
    fn s5034_keeps_local_function_consumption_out_of_parent_scope() {
        let report = analyze_default(
            "class C\n{\n    async Task Outer()\n    {\n        ValueTask<int> pending = Load();\n        var value = await pending;\n        async Task Local()\n        {\n            ValueTask<int> pending = Load();\n            var value = await pending;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5034").is_empty());
    }

    #[test]
    fn s5034_does_not_merge_same_named_sibling_block_locals() {
        let report = analyze_default(
            "class C\n{\n    async Task M()\n    {\n        {\n            ValueTask<int> pending = Load();\n            var value = await pending;\n        }\n        {\n            ValueTask<int> pending = Load();\n            var value = await pending;\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5034").is_empty());
    }

    #[test]
    fn s5034_anchors_earliest_mixed_consumption() {
        let report = analyze_default(
            "class C\n{\n    async Task M()\n    {\n        ValueTask<int> pending = Load();\n        var first = pending.Result;\n        var second = await pending;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5034");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
