use crate::cst::{collect_kinds, node_text, parameters_of};
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
/// destructors, operators, accessors, local functions, and closures.
pub(crate) fn callable_blocks(root: Node<'_>) -> Vec<Node<'_>> {
    const CALLABLE_KINDS: [&str; 8] = [
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "operator_declaration",
        "accessor_declaration",
        "local_function_statement",
        "lambda_expression",
        "anonymous_method_expression",
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
    for closure in collect_kinds(
        body,
        &[
            "lambda_expression",
            "anonymous_method_expression",
            "local_function_statement",
        ],
    ) {
        let declared = closure_declared_names(closure, source);
        for identifier in collect_kinds(closure, &["identifier"]) {
            let name = node_text(identifier, source);
            if !declared.contains(name) {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

fn closure_declared_names<'a>(
    closure: Node<'_>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    let mut names = std::collections::HashSet::new();
    if let Some(parameters) = closure.child_by_field_name("parameters")
        && parameters.kind() == "identifier"
    {
        names.insert(node_text(parameters, source));
    }
    for parameter in parameters_of(closure) {
        if let Some(name) = parameter.child_by_field_name("name") {
            names.insert(node_text(name, source));
        }
    }
    for declarator in collect_kinds(closure, &["variable_declarator"]) {
        if let Some(name) = declarator.child_by_field_name("name") {
            names.insert(node_text(name, source));
        }
    }
    names
}

/// Signed constant value of an integer literal, a `MinValue`/`MaxValue`
/// identifier, or a negation/parenthesization thereof.
pub(crate) fn constant_integer_value(expression: Node<'_>, source: &str) -> Option<i128> {
    let mut current = expression;
    let mut negated = false;
    loop {
        match current.kind() {
            "parenthesized_expression" => current = first_named_child(current)?,
            "prefix_unary_expression" if unary_operator(current) == Some("-") => {
                negated = !negated;
                current = first_named_child(current)?;
            }
            _ => break,
        }
    }
    let value = match current.kind() {
        "integer_literal" => integer_literal_value(node_text(current, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(i128::from),
        // `int.MaxValue` parses as a member access, not an identifier,
        // so the known-constant table keys on text alone.
        _ => match node_text(current, source) {
            "int.MinValue" | "Int32.MinValue" => Some(i128::from(i32::MIN)),
            "int.MaxValue" | "Int32.MaxValue" => Some(i128::from(i32::MAX)),
            "short.MinValue" => Some(i128::from(i16::MIN)),
            "short.MaxValue" => Some(i128::from(i16::MAX)),
            "long.MinValue" | "Int64.MinValue" => Some(i128::from(i64::MIN)),
            "long.MaxValue" | "Int64.MaxValue" => Some(i128::from(i64::MAX)),
            _ => None,
        },
    }?;
    Some(if negated { -value } else { value })
}

/// Pre-order walk owned by one callable. Nested callables execute in a
/// different dataflow scope and are therefore visited only by their own
/// [`callable_blocks`] entry.
pub(crate) fn walk_owned<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        visit(current);
        if is_nested_callable(current) {
            continue;
        }
        push_children_in_document_order(current, &mut pending);
    }
}

/// Collects nodes belonging to one callable, without leaking through a
/// local function, lambda, or anonymous-method boundary.
pub(crate) fn collect_owned_kinds<'t>(root: Node<'t>, kinds: &[&str]) -> Vec<Node<'t>> {
    let mut matched = Vec::new();
    walk_owned(root, &mut |node| {
        if kinds.contains(&node.kind()) {
            matched.push(node);
        }
    });
    matched
}

/// Pre-order walk that does not descend into `block` nodes or nested
/// callables; used when the owning statement list visits blocks itself.
pub(crate) fn walk_except_blocks<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        visit(current);
        if current.kind() == "block" || is_nested_callable(current) {
            continue;
        }
        push_children_in_document_order(current, &mut pending);
    }
}

fn is_nested_callable(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "local_function_statement" | "lambda_expression" | "anonymous_method_expression"
    )
}

fn push_children_in_document_order<'t>(node: Node<'t>, pending: &mut Vec<Node<'t>>) {
    let mut cursor = node.walk();
    let mut children: Vec<_> = node.children(&mut cursor).collect();
    children.reverse();
    pending.extend(children);
}

/// Names guarded inside one callable by a `HasValue` check, explicit
/// null comparison, `is not null` pattern, or null-conditional access.
pub(crate) fn guarded_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut guarded = std::collections::HashSet::new();
    walk_owned(body, &mut |node| {
        if node.kind() != "identifier" {
            return;
        }
        let Some(parent) = node.parent().filter(|parent| {
            matches!(
                parent.kind(),
                "member_access_expression"
                    | "binary_expression"
                    | "is_pattern_expression"
                    | "conditional_access_expression"
            )
        }) else {
            return;
        };
        let name = node_text(node, source);
        let text = node_text(parent, source);
        if [
            format!("{name}.HasValue"),
            format!("{name} != null"),
            format!("{name} is not null"),
            format!("{name}?."),
        ]
        .iter()
        .any(|pattern| text.contains(pattern))
        {
            guarded.insert(name.to_owned());
        }
    });
    guarded
}
