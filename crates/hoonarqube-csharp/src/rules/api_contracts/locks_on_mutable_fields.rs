use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
};
use crate::rules::expressions::enclosing_type;
use crate::rules::logging::field_declarator_names;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2445 — mutable lock fields invite swapped guards.
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
        if has_shadowing_binding(lock_statement, name, source) {
            continue;
        }
        let Some(owner) = enclosing_type(lock_statement) else {
            continue;
        };
        let field = type_members(owner).into_iter().find(|member| {
            member.kind() == "field_declaration"
                && field_declarator_names(*member, source).contains(&name)
        });
        let Some(field) = field else {
            continue;
        };
        if !has_modifier(&modifiers_of(field, source), "readonly") {
            issues.push(issue(
                language,
                "S2445",
                format!("Do not lock on writable field '{name}', use a readonly field instead."),
                range_of(expression, source),
            ));
        }
    }
    issues
}

fn has_shadowing_binding(use_site: Node<'_>, name: &str, source: &str) -> bool {
    let Some(callable) = enclosing_callable(use_site) else {
        return false;
    };
    let parameter = collect_kinds(callable, &["parameter"])
        .into_iter()
        .filter(|parameter| enclosing_callable(*parameter) == Some(callable))
        .any(|parameter| {
            parameter
                .child_by_field_name("name")
                .is_some_and(|declared| node_text(declared, source) == name)
        });
    parameter
        || collect_kinds(callable, &["variable_declarator"])
            .into_iter()
            .filter(|declaration| enclosing_callable(*declaration) == Some(callable))
            .filter(|declaration| declaration.start_byte() < use_site.start_byte())
            .filter(|declaration| {
                declaration_scope(*declaration)
                    .is_some_and(|scope| ancestors_of(use_site).any(|ancestor| ancestor == scope))
            })
            .any(|declaration| {
                declaration
                    .child_by_field_name("name")
                    .is_some_and(|declared| node_text(declared, source) == name)
            })
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
    fn s2445_flags_static_mutable_lock_fields() {
        let report = analyze_default(
            "class A\n{\n    static object shared;\n    void M()\n    {\n        lock (shared) { Work(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2445").len(), 1);
    }
    #[test]
    fn s2445_flags_lock_on_field_in_later_declaration() {
        let report = analyze_default(
            "class A\n{\n    static object first;\n    static object second;\n    void M()\n    {\n        lock (second) { Work(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2445").len(), 1);
    }

    #[test]
    fn s2445_does_not_confuse_parameters_or_locals_with_fields() {
        let report = analyze_default(
            "class A\n{\n    object gate;\n    object other;\n    void WithParameter(object gate)\n    {\n        lock (gate) { Work(); }\n    }\n    void WithLocal()\n    {\n        var other = new object();\n        lock (other) { Work(); }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2445").is_empty());
    }

    #[test]
    fn s2445_ignores_out_of_scope_and_later_local_names() {
        let report = analyze_default(
            "class A\n{\n    object gate;\n    object other;\n    void M()\n    {\n        { var gate = new object(); }\n        lock (gate) { Work(); }\n        lock (other) { Work(); }\n        var other = new object();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2445").len(), 2);
    }
}
