use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::structure::body_of;
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
        let local_lock = enclosing_method(lock_statement)
            .and_then(|method| body_of(method))
            .is_some_and(|body| {
                collect_kinds(body, &["variable_declarator"])
                    .iter()
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
                "Do not lock on this local variable.",
                range_of(lock_statement),
            ));
        }
    }
    issues
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
}
