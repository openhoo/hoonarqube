use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2997 — disposables returned from inside their own `using`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for using_statement in collect_kinds(root, &["using_statement"]) {
        if is_error_tainted(using_statement) {
            continue;
        }
        let resource = collect_kinds(using_statement, &["variable_declaration"])
            .into_iter()
            .next();
        let body = collect_kinds(using_statement, &["block"])
            .into_iter()
            .next();
        let (Some(resource), Some(body)) = (resource, body) else {
            continue;
        };
        for declarator in collect_kinds(resource, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let creates_disposable = declarator_initializer(declarator, name)
                .is_some_and(|initializer| initializer.kind() == "object_creation_expression");
            if !creates_disposable {
                continue;
            }
            for return_statement in collect_kinds(body, &["return_statement"]) {
                let returns_variable =
                    first_named_child(return_statement).is_some_and(|expression| {
                        expression.kind() == "identifier"
                            && node_text(expression, source) == node_text(name, source)
                    });
                if returns_variable {
                    issues.push(issue(
                        language,
                        "S2997",
                        format!(
                            "'{}' is disposed by its using statement; return it from outside.",
                            node_text(name, source)
                        ),
                        range_of(return_statement),
                    ));
                }
            }
        }
    }
    issues
}
