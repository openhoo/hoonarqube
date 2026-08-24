use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{
    callee_name, comparisons, expression_name, first_named_child, invocation_arguments,
    invocation_function, operator_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3900 — public methods validate annotated nullable
/// reference parameters before using them. Restricted to `?`-annotated
/// parameters so single-file analysis stays sound.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for parameter in parameters_of(method) {
            if is_error_tainted(parameter)
                || modifiers_of(parameter, source)
                    .iter()
                    .any(|modifier| matches!(*modifier, "this"))
            {
                continue;
            }
            let Some(type_node) = parameter.child_by_field_name("type") else {
                continue;
            };
            if !node_text(type_node, source).trim().ends_with('?') {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, source);
            if null_guards_parameter(body, name, source) {
                continue;
            }
            let dereference = collect_kinds(body, &["identifier"])
                .into_iter()
                .find(|identifier| {
                    !is_error_tainted(*identifier)
                        && node_text(*identifier, source) == name
                        && identifier.parent().is_some_and(|parent| {
                            matches!(
                                parent.kind(),
                                "member_access_expression"
                                    | "element_access_expression"
                                    | "element_binding_expression"
                            ) && first_named_child(parent)
                                .is_some_and(|base| base.id() == identifier.id())
                                || (parent.kind() == "invocation_expression"
                                    && invocation_function(parent) == Some(*identifier))
                        })
                });
            if let Some(dereference) = dereference {
                issues.push(issue(
                    language,
                    "S3900",
                    format!("Validate parameter '{name}' against null before using it."),
                    range_of(dereference),
                ));
            }
        }
    }
    issues
}

/// Whether the body guards `parameter` against null explicitly.
fn null_guards_parameter(body: Node<'_>, parameter: &str, source: &str) -> bool {
    let comparison_guard = comparisons(body).iter().any(|(expression, left, right)| {
        matches!(operator_of(*expression), Some("==" | "!="))
            && [left, right]
                .iter()
                .any(|side| side.kind() == "identifier" && node_text(**side, source) == parameter)
            && [left, right]
                .iter()
                .any(|side| side.kind() == "null_literal")
    });
    comparison_guard
        || node_text(body, source).contains(&format!("{parameter} is null"))
        || node_text(body, source).contains(&format!("{parameter} is not null"))
        || collect_kinds(body, &["invocation_expression"])
            .iter()
            .any(|invocation| {
                callee_name(*invocation, source)
                    .is_some_and(|callee| callee.ends_with("ThrowIfNull"))
                    && invocation_arguments(*invocation)
                        .iter()
                        .any(|argument| expression_name(*argument, source) == Some(parameter))
            })
}
