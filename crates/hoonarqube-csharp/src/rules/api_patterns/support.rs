use crate::cst::{collect_kinds, is_error_tainted, node_text, simple_name};
use crate::rules::expressions::callee_name;
use crate::rules::literals::{assignment_target_name, declarator_initializer};
use tree_sitter::Node;

/// Expressions of every attribute argument directly attached to a node
/// (`[Export(typeof(I))]` yields `typeof(I)`).
pub(crate) fn attribute_argument_texts<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut texts = Vec::new();
    for attribute in collect_kinds(node, &["attribute"]) {
        for argument in collect_kinds(attribute, &["attribute_argument"]) {
            if let Some(value) = argument
                .children(&mut argument.walk())
                .find(tree_sitter::Node::is_named)
            {
                texts.push(node_text(value, source));
            }
        }
    }
    texts
}

/// Validation that throws argument exceptions eagerly: a `throw` of an
/// `Argument*` exception or a `ThrowIf*` guard call.
pub(crate) fn is_validation_statement(statement: Node<'_>, source: &str) -> bool {
    let throws_argument_exception = statement.kind() == "throw_statement"
        && collect_kinds(statement, &["object_creation_expression"])
            .into_iter()
            .any(|creation| {
                creation
                    .child_by_field_name("type")
                    .is_some_and(|type_node| {
                        simple_name(node_text(type_node, source)).starts_with("Argument")
                    })
            });
    throws_argument_exception
        || collect_kinds(statement, &["invocation_expression"])
            .into_iter()
            .any(|call| callee_name(call, source).is_some_and(|name| name.starts_with("ThrowIf")))
}

/// Validation statements of a body, in document order.
pub(crate) fn validation_statements<'t>(body: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(body, &["throw_statement", "expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| is_validation_statement(*statement, source))
        .collect()
}

/// Stores of `DateTime.Now` into instant-named targets, in document
/// order: `(target name, node)`.
pub(crate) fn local_now_stores<'t, 's>(
    body: Node<'t>,
    source: &'s str,
) -> Vec<(&'s str, Node<'t>)> {
    let mut stores = Vec::new();
    for assignment in collect_kinds(body, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(target) = assignment_target_name(left, source) else {
            continue;
        };
        if let Some(right) = assignment.child_by_field_name("right")
            && node_text(right, source) == "DateTime.Now"
        {
            stores.push((target, assignment));
        }
    }
    for declarator in collect_kinds(body, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        if let Some(value) = declarator_initializer(declarator, name)
            && node_text(value, source) == "DateTime.Now"
        {
            stores.push((node_text(name, source), declarator));
        }
    }
    stores
}
