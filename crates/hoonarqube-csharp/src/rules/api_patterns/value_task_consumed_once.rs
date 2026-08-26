use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{expression_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5034 — a `ValueTask` may be consumed exactly once;
/// awaiting it twice corrupts state. Bound: locals and parameters typed
/// `ValueTask…`, consumption via `await`/`.Result`/`.AsTask()`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let value_task_locals: std::collections::HashSet<String> =
        collect_kinds(root, &["variable_declarator"])
            .into_iter()
            .filter(|declarator| {
                declarator
                    .parent()
                    .and_then(|parent| parent.child_by_field_name("type"))
                    .is_some_and(|type_node| {
                        simple_name(node_text(type_node, source)) == "ValueTask"
                    })
            })
            .filter_map(|declarator| declarator.child_by_field_name("name"))
            .map(|name| node_text(name, source).to_owned())
            .collect();
    if value_task_locals.is_empty() {
        return Vec::new();
    }
    let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut issues = Vec::new();
    let mut record_consumption = |name: Option<&str>, node: Node<'_>, issues: &mut Vec<Issue>| {
        if let Some(name) = name
            && value_task_locals.contains(name)
        {
            if consumed.contains(name) {
                issues.push(issue(
                    language,
                    "S5034",
                    format!("'{name}' is consumed more than once."),
                    range_of(node, source),
                ));
            }
            consumed.insert(name.to_owned());
        }
    };
    for await_expression in collect_kinds(root, &["await_expression"]) {
        let operand = first_named_child(await_expression);
        record_consumption(
            operand
                .filter(|operand| operand.kind() == "identifier")
                .map(|operand| node_text(operand, source)),
            await_expression,
            &mut issues,
        );
    }
    for access in collect_kinds(root, &["member_access_expression"]) {
        let member = expression_name(access, source).unwrap_or("");
        if matches!(member, "Result" | "AsTask" | "GetAwaiter") {
            let base = access.child_by_field_name("expression");
            record_consumption(
                base.filter(|base| base.kind() == "identifier")
                    .map(|base| node_text(base, source)),
                access,
                &mut issues,
            );
        }
    }
    issues
}
