use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of, simple_name};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::has_modifier;
use crate::rules::security::return_type_text;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4586 — non-async `Task` methods must not return null; there
/// is no completed task to await in null.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| is_non_async_task_method(*method, source))
        .flat_map(|method| null_returns(method).into_iter())
        .map(|null| {
            issue(
                    language,
                    "S4586",
                    "Do not return null from this method, instead return 'Task.FromResult<T>(null)', 'Task.CompletedTask' or 'Task.Delay(0)'.",
                    range_of(null, source),
                )
        })
        .collect()
}

fn is_non_async_task_method(method: Node<'_>, source: &str) -> bool {
    !is_error_tainted(method)
        && !has_modifier(&modifiers_of(method, source), "async")
        && simple_name(return_type_text(method, source)) == "Task"
}

fn null_returns(method: Node<'_>) -> Vec<Node<'_>> {
    if let Some(body) = body_of(method) {
        return collect_kinds(body, &["return_statement"])
            .into_iter()
            .filter(|statement| belongs_to_method(*statement, method))
            .filter_map(null_value)
            .collect();
    }
    direct_child_of_kind(method, "arrow_expression_clause")
        .and_then(null_value)
        .into_iter()
        .collect()
}

fn direct_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn null_value(node: Node<'_>) -> Option<Node<'_>> {
    let mut value = first_named_child(node)?;
    while value.kind() == "parenthesized_expression" {
        value = first_named_child(value)?;
    }
    (value.kind() == "null_literal").then_some(value)
}

fn belongs_to_method(node: Node<'_>, method: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.id() == method.id() {
            return true;
        }
        if matches!(
            ancestor.kind(),
            "local_function_statement" | "lambda_expression" | "anonymous_method_expression"
        ) {
            return false;
        }
        current = ancestor.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4586_flags_generic_task_returns_and_counts_each() {
        let report = analyze_default(
            "class A\n{\n    Task<int> First()\n    {\n        if (ready) { return null; }\n        return Task.FromResult(1);\n    }\n\n    Task Second() { return null; }\n\n    int Plain() { return null; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4586");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s4586_ignores_bodyless_interface_declarations() {
        let report = analyze_default(
            "interface IWorker\n{\n    Task Work();\n\n    Task<int> Fetch();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4586").is_empty());
    }

    #[test]
    fn s4586_keeps_returns_inside_nested_callables_out_of_the_outer_method() {
        let report = analyze_default(
            "class A\n{\n    Task Work()\n    {\n        object Local() { return null; }\n        Func<object> deferred = () => { return null; };\n        return Task.CompletedTask;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4586").is_empty());
    }

    #[test]
    fn s4586_flags_expression_bodied_and_parenthesized_nulls() {
        let report = analyze_default(
            "class A\n{\n    Task First() => null;\n\n    Task Second()\n    {\n        return ((null));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4586");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 7);
    }
}
