use crate::cst::{collect_kinds, node_text};
use crate::rules::expressions::{first_named_child, integer_literal_value, operator_of};
use crate::rules::structure::body_of;
use tree_sitter::Node;
pub(crate) fn unary_operator(expression: Node<'_>) -> Option<&'static str> {
    let mut cursor = expression.walk();
    expression
        .children(&mut cursor)
        .find(|child| {
            !child.is_named() && matches!(child.kind(), "!" | "~" | "+" | "-" | "++" | "--")
        })
        .map(|token| token.kind())
}

/// How an identifier occurrence acts as a pure write, if it does at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteKind {
    /// `x = …` replaces the previous value outright.
    Store,
    /// `x++` / `--x` read the value and overwrite it in one step.
    Increment,
}

/// Whether this identifier occurrence is a pure write target: the left
/// side of a plain `=` assignment, a `++`/`--` operand, or a declared
/// name. Compound assignments (`+=`) read first and never classify
/// here; plain call arguments are reads, so `out`/`ref` writes simply
/// stay untracked (conservative by design).
pub(crate) fn identifier_write(node: Node<'_>) -> Option<WriteKind> {
    let parent = node.parent()?;
    match parent.kind() {
        "assignment_expression" => {
            let is_store = operator_of(parent) == Some("=")
                && parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == node.id());
            is_store.then_some(WriteKind::Store)
        }
        "prefix_unary_expression" | "postfix_unary_expression" => {
            matches!(unary_operator(parent), Some("++" | "--")).then_some(WriteKind::Increment)
        }
        "variable_declarator" => {
            let is_name = parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id());
            is_name.then_some(WriteKind::Store)
        }
        _ => None,
    }
}

/// Bodies of callables that carry a block: methods, constructors,
/// destructors, operators, accessors, and local functions.
pub(crate) fn callable_blocks(root: Node<'_>) -> Vec<Node<'_>> {
    const CALLABLE_KINDS: [&str; 6] = [
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "operator_declaration",
        "accessor_declaration",
        "local_function_statement",
    ];
    collect_kinds(root, &CALLABLE_KINDS)
        .into_iter()
        .filter_map(body_of)
        .collect()
}

/// Names read inside a lambda, anonymous method, or local function —
/// their lifetimes escape the enclosing block, so dead-store tracking
/// skips them entirely.
pub(crate) fn captured_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for closure in collect_kinds(body, &["lambda_expression", "anonymous_method_expression"]) {
        for identifier in collect_kinds(closure, &["identifier"]) {
            names.insert(node_text(identifier, source).to_owned());
        }
    }
    names
}

/// Signed constant value of an integer literal, a `MinValue`/`MaxValue`
/// identifier, or a negation/parenthesization thereof.
pub(crate) fn constant_integer_value(expression: Node<'_>, source: &str) -> Option<i128> {
    match expression.kind() {
        "integer_literal" => integer_literal_value(node_text(expression, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(i128::from),
        "parenthesized_expression" => {
            first_named_child(expression).and_then(|inner| constant_integer_value(inner, source))
        }
        "prefix_unary_expression" if unary_operator(expression) == Some("-") => {
            first_named_child(expression)
                .and_then(|operand| constant_integer_value(operand, source))
                .map(|value| -value)
        }
        // `int.MaxValue` parses as a member access, not an identifier,
        // so the known-constant table keys on text alone.
        _ => match node_text(expression, source) {
            "int.MinValue" | "Int32.MinValue" => Some(i128::from(i32::MIN)),
            "int.MaxValue" | "Int32.MaxValue" => Some(i128::from(i32::MAX)),
            "short.MinValue" => Some(i128::from(i16::MIN)),
            "short.MaxValue" => Some(i128::from(i16::MAX)),
            "long.MinValue" | "Int64.MinValue" => Some(i128::from(i64::MIN)),
            "long.MaxValue" | "Int64.MaxValue" => Some(i128::from(i64::MAX)),
            _ => None,
        },
    }
}

/// Pre-order walk that does not descend into `block` nodes; used when
/// the enclosing statement list already visits those blocks separately.
pub(crate) fn walk_except_blocks<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    visit(node);
    if node.kind() == "block" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_except_blocks(child, visit);
    }
}

/// Whether the member body guards `name` somewhere: a `HasValue` check,
/// an explicit null comparison, an `is not null` pattern, or a
/// null-conditional access. Guarded names are exempt entirely.
pub(crate) fn name_is_guarded(body_text: &str, name: &str) -> bool {
    [
        "{name}.HasValue",
        "{name} != null",
        "{name} is not null",
        "{name}?.",
    ]
    .iter()
    .any(|pattern| body_text.contains(pattern.replace("{name}", name).as_str()))
}
