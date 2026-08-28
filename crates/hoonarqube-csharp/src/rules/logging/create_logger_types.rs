use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{
    callee_name, enclosing_type, first_named_child, invocation_arguments, invocation_function,
};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3416 — `CreateLogger<T>` must name the enclosing type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let Some((target, target_node)) = create_logger_target(call, source) else {
            continue;
        };
        let Some(enclosing) = enclosing_type(call) else {
            continue;
        };
        let Some(name) = enclosing.child_by_field_name("name") else {
            continue;
        };
        if simple_name(&target) != node_text(name, source) {
            issues.push(issue(
                language,
                "S3416",
                "Update this logger to use its enclosing type.",
                range_of(target_node, source),
            ));
        }
    }
    issues
}

/// The type named by `CreateLogger<T>()` or `CreateLogger(typeof(T))`.
fn create_logger_target<'t>(call: Node<'t>, source: &str) -> Option<(String, Node<'t>)> {
    let function = invocation_function(call)?;
    let target_node = if function.kind() == "member_access_expression" {
        let mut cursor = function.walk();
        let generic = function
            .children(&mut cursor)
            .find(|child| child.kind() == "generic_name")
            .filter(|generic| {
                first_named_child(*generic)
                    .is_some_and(|identifier| node_text(identifier, source) == "CreateLogger")
            })?;
        let mut generic_cursor = generic.walk();
        generic
            .children(&mut generic_cursor)
            .find(|child| child.kind() == "type_argument_list")?
    } else {
        if callee_name(call, source) != Some("CreateLogger") {
            return None;
        }
        let argument = invocation_arguments(call).into_iter().next()?;
        let expression = argument_expression(argument);
        (expression.kind() == "typeof_expression").then_some(expression)?
    };
    let mut target_cursor = target_node.walk();
    let node = target_node
        .children(&mut target_cursor)
        .find(tree_sitter::Node::is_named)?;
    Some((node_text(node, source).to_string(), node))
}
