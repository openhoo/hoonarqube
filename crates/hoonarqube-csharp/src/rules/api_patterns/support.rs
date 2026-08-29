use crate::cst::{collect_kinds, direct_attributes, is_error_tainted, node_text, simple_name};
use crate::rules::expressions::callee_name;
use crate::rules::literals::{assignment_target_name, declarator_initializer};
use tree_sitter::Node;

/// Collects matching nodes in one callable body without entering nested
/// local functions or closures. Those nodes have independent names and
/// execution lifetimes, so pairing their operations with the enclosing
/// callable produces false positives.
pub(crate) fn collect_kinds_in_callable<'t>(body: Node<'t>, kinds: &[&str]) -> Vec<Node<'t>> {
    const NESTED_CALLABLES: [&str; 3] = [
        "local_function_statement",
        "lambda_expression",
        "anonymous_method_expression",
    ];

    let mut matched = Vec::new();
    let mut pending = vec![body];
    while let Some(current) = pending.pop() {
        if current.id() != body.id() && NESTED_CALLABLES.contains(&current.kind()) {
            continue;
        }
        if kinds.contains(&current.kind()) {
            matched.push(current);
        }
        for index in (0..current.child_count()).rev() {
            pending.push(
                current
                    .child(index)
                    .expect("an index below child_count must identify a child"),
            );
        }
    }
    matched
}

/// Expressions of every attribute argument directly attached to a node
/// (`[Export(typeof(I))]` yields `typeof(I)`).
pub(crate) fn attribute_argument_texts<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut texts = Vec::new();
    let attributes = if node.kind() == "attribute" {
        vec![node]
    } else {
        direct_attributes(node)
    };
    for attribute in attributes {
        for argument in collect_kinds(attribute, &["attribute_argument"]) {
            if let Some(value) = argument
                .children(&mut argument.walk())
                .filter(tree_sitter::Node::is_named)
                .last()
            {
                texts.push(node_text(value, source));
            }
        }
    }
    texts
}

/// Validation that throws argument exceptions eagerly: a `throw` of an
/// `Argument*` exception or a `ThrowIf*` guard call.
fn is_validation_statement(statement: Node<'_>, source: &str) -> bool {
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
    let calls_throw_if = statement.kind() == "expression_statement"
        && statement
            .children(&mut statement.walk())
            .find(tree_sitter::Node::is_named)
            .filter(|expression| expression.kind() == "invocation_expression")
            .and_then(|call| callee_name(call, source))
            .is_some_and(|name| name.starts_with("ThrowIf"));
    throws_argument_exception || calls_throw_if
}

/// Validation statements of a body, in document order.
pub(crate) fn validation_statements<'t>(body: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds_in_callable(body, &["throw_statement", "expression_statement"])
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
    for node in collect_kinds_in_callable(body, &["assignment_expression", "variable_declarator"]) {
        match node.kind() {
            "assignment_expression" => {
                let Some(left) = node.child_by_field_name("left") else {
                    continue;
                };
                let Some(target) = assignment_target_name(left, source) else {
                    continue;
                };
                if node
                    .child_by_field_name("right")
                    .is_some_and(|right| node_text(right, source) == "DateTime.Now")
                {
                    stores.push((target, node));
                }
            }
            "variable_declarator" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                if declarator_initializer(node, name)
                    .is_some_and(|value| node_text(value, source) == "DateTime.Now")
                {
                    stores.push((node_text(name, source), node));
                }
            }
            _ => {}
        }
    }
    stores
}
