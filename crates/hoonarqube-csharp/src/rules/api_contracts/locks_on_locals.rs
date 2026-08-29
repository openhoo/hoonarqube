use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6507 — locals are per-call, so locking on them guards
/// nothing shared.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lock_statement in collect_kinds(root, &["lock_statement"]) {
        if is_error_tainted(lock_statement) {
            continue;
        }
        let Some(expression) = lock_guard_expression(lock_statement) else {
            continue;
        };
        if expression.kind() != "identifier" {
            continue;
        }
        let name = node_text(expression, source);
        let local_lock = enclosing_callable(lock_statement).is_some_and(|callable| {
            collect_kinds(callable, &["variable_declarator"])
                .into_iter()
                .filter(|declarator| {
                    enclosing_callable(*declarator) == enclosing_callable(lock_statement)
                })
                .filter(|declarator| declarator.start_byte() < lock_statement.start_byte())
                .filter(|declarator| {
                    declaration_scope(*declarator).is_some_and(|scope| {
                        ancestors_of(lock_statement).any(|ancestor| ancestor == scope)
                    })
                })
                .any(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .is_some_and(|declared| node_text(declared, source) == name)
                })
        });
        if local_lock {
            issues.push(issue(
                language,
                "S6507",
                format!("Do not lock on local variable '{name}', use a readonly field instead."),
                range_of(expression, source),
            ));
        }
    }
    issues
}

fn declaration_scope(declaration: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(declaration).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "block"
                | "for_statement"
                | "foreach_statement"
                | "using_statement"
                | "fixed_statement"
                | "switch_section"
        )
    })
}

fn enclosing_callable(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "accessor_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
                | "local_function_statement"
                | "anonymous_method_expression"
                | "lambda_expression"
        )
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6507_parameters_and_fields_are_not_locals() {
        let report = analyze_default(
            "class A\n{\n    object field = new object();\n    void M(object gate)\n    {\n        lock (gate) { }\n        lock (field) { }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6507").is_empty());
    }

    #[test]
    fn s6507_counts_each_lock_on_a_local() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var local = new object();\n        lock (local) { Work(); }\n        lock (local) { Again(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6507").len(), 2);
    }

    #[test]
    fn s6507_does_not_leak_declarations_from_nested_callables() {
        let report = analyze_default(
            "class A\n{\n    object gate = new object();\n    void M()\n    {\n        void Nested()\n        {\n            var gate = new object();\n            lock (gate) { Work(); }\n        }\n        lock (gate) { Work(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6507");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);
    }

    #[test]
    fn s6507_requires_a_preceding_declaration_in_an_enclosing_scope() {
        let report = analyze_default(
            "class A\n{\n    object first = new object();\n    object second = new object();\n    void M()\n    {\n        { var first = new object(); }\n        lock (first) { Work(); }\n        lock (second) { Work(); }\n        var second = new object();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6507").is_empty());
    }

    #[test]
    fn s6507_checks_constructor_locals() {
        let report = analyze_default(
            "class A\n{\n    A()\n    {\n        var gate = new object();\n        lock (gate) { Work(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6507").len(), 1);
    }
}
