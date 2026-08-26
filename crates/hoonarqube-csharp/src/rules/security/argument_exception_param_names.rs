use super::support::call_argument_nodes;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::expressions::creation_type_text;
use crate::rules::literals::{argument_expression, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3928 — the 'paramName' argument must name a parameter that
/// actually exists on the throwing method.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const ARGUMENT_EXCEPTION_TYPES: [&str; 3] = [
        "ArgumentException",
        "ArgumentNullException",
        "ArgumentOutOfRangeException",
    ];
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if !ARGUMENT_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(creation, source))) {
            continue;
        }
        let arguments = call_argument_nodes(creation);
        if arguments.len() < 2 {
            continue;
        }
        let value = argument_expression(arguments[1]);
        if value.kind() != "string_literal" {
            continue;
        }
        let wanted = literal_inner_text(value, source);
        let Some(method) = enclosing_method(creation) else {
            continue;
        };
        let known = parameters_of(method).iter().any(|param| {
            param
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == wanted)
        });
        if !known {
            issues.push(issue(
                language,
                "S3928",
                "Pass an existing parameter name to this exception.",
                range_of(creation, source),
            ));
        }
    }
    issues
}
