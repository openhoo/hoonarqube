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
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        if simple_name(return_type_text(method, source)) != "Task" {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for statement in collect_kinds(body, &["return_statement"]) {
            let returns_null = first_named_child(statement)
                .is_some_and(|expression| expression.kind() == "null_literal");
            if returns_null {
                issues.push(issue(
                    language,
                    "S4586",
                    "Return 'Task.CompletedTask' instead of null.",
                    range_of(statement, source),
                ));
            }
        }
    }
    issues
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
}
