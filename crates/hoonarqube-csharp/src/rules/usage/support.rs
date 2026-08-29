use crate::cst::{ancestors_of, node_text};
use tree_sitter::Node;

/// One private member candidate for the S1144 audit.
pub(crate) struct PrivateMember<'t> {
    pub(crate) anchor: Node<'t>,
    pub(crate) owner: Node<'t>,
    pub(crate) name: String,
    pub(crate) kind_word: &'static str,
}

/// Variable declarators owned directly by a field/event/local declaration.
/// A recursive collection would also pick up declarations inside lambdas in
/// an initializer, causing the nested declaration to be audited twice.
pub(crate) fn direct_variable_declarators(declaration: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = declaration.walk();
    let Some(variable_declaration) = declaration
        .named_children(&mut cursor)
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut variable_cursor = variable_declaration.walk();
    variable_declaration
        .named_children(&mut variable_cursor)
        .filter(|child| child.kind() == "variable_declarator")
        .collect()
}

/// Whether an identifier introduces a binding instead of reading one.
fn introduces_binding(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "variable_declarator"
            | "parameter"
            | "catch_declaration"
            | "enum_member_declaration"
            | "single_variable_designation"
    ) {
        return true;
    }
    if matches!(parent.kind(), "foreach_statement" | "from_clause")
        && matches!(
            parent.child_by_field_name(if parent.kind() == "foreach_statement" {
                "left"
            } else {
                "name"
            }),
            Some(binding) if binding == identifier
        )
    {
        return true;
    }
    if matches!(
        parent.kind(),
        "let_clause" | "join_clause" | "join_into_clause"
    ) && directly_contains_identifier(parent, identifier)
    {
        return true;
    }
    (parent.kind().ends_with("_declaration") || parent.kind() == "local_function_statement")
        && parent.child_by_field_name("name") == Some(identifier)
}

/// Whether an identifier is executable-code usage rather than a declaration,
/// named-argument label, or member name reached through another receiver.
fn is_value_reference(identifier: Node<'_>, local: bool) -> bool {
    if introduces_binding(identifier) {
        return false;
    }
    let Some(parent) = identifier.parent() else {
        return true;
    };
    if matches!(parent.kind(), "name_colon" | "name_equals")
        || (parent.kind() == "argument" && parent.child_by_field_name("name") == Some(identifier))
    {
        return false;
    }
    !(local
        && matches!(
            parent.kind(),
            "member_access_expression" | "member_binding_expression" | "qualified_name"
        )
        && parent.child_by_field_name("name") == Some(identifier))
}

fn is_qualified_member_name(identifier: Node<'_>) -> bool {
    identifier.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "member_access_expression" | "member_binding_expression"
        ) && parent.child_by_field_name("name") == Some(identifier)
    })
}

fn directly_contains_identifier(node: Node<'_>, identifier: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "identifier")
        == Some(identifier)
}

fn shadowing_scope(binding: Node<'_>) -> Option<Node<'_>> {
    let parent = binding.parent()?;
    match parent.kind() {
        "parameter" => ancestors_of(parent).find(|ancestor| {
            matches!(
                ancestor.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "local_function_statement"
                    | "lambda_expression"
                    | "anonymous_method_expression"
            )
        }),
        "variable_declarator" => {
            let container = ancestors_of(parent).find(|ancestor| {
                matches!(
                    ancestor.kind(),
                    "local_declaration_statement"
                        | "for_statement"
                        | "using_statement"
                        | "fixed_statement"
                )
            })?;
            if container.kind() == "local_declaration_statement" {
                ancestors_of(container).find(|ancestor| {
                    matches!(
                        ancestor.kind(),
                        "block" | "switch_body" | "compilation_unit"
                    )
                })
            } else {
                Some(container)
            }
        }
        "catch_declaration" => {
            ancestors_of(parent).find(|ancestor| ancestor.kind() == "catch_clause")
        }
        "single_variable_designation" => {
            ancestors_of(parent).find(|ancestor| matches!(ancestor.kind(), "block" | "switch_body"))
        }
        "local_function_statement" => {
            ancestors_of(parent).find(|ancestor| matches!(ancestor.kind(), "block" | "switch_body"))
        }
        "foreach_statement" if parent.child_by_field_name("left") == Some(binding) => Some(parent),
        "from_clause" if parent.child_by_field_name("name") == Some(binding) => {
            ancestors_of(parent).find(|ancestor| ancestor.kind() == "query_expression")
        }
        "let_clause" | "join_clause" | "join_into_clause"
            if directly_contains_identifier(parent, binding) =>
        {
            ancestors_of(parent).find(|ancestor| ancestor.kind() == "query_expression")
        }
        _ => None,
    }
}

fn shadowing_ranges(scope: Node<'_>, name: &str, source: &str) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut pending = vec![scope];
    while let Some(node) = pending.pop() {
        let binding_scope =
            if node.kind() == "implicit_parameter" && node_text(node, source) == name {
                node.parent()
            } else if node.kind() == "identifier"
                && node_text(node, source) == name
                && introduces_binding(node)
            {
                shadowing_scope(node)
            } else {
                None
            };
        if let Some(binding_scope) = binding_scope {
            let range = binding_scope.byte_range();
            if !ranges.contains(&range) {
                ranges.push(range);
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    ranges
}

/// Whether `root` contains a real identifier reference. Traversal is
/// iterative so adversarially deep syntax cannot exhaust the Rust stack.
fn mentions_identifier(
    root: Node<'_>,
    name: &str,
    source: &str,
    after_byte: usize,
    local: bool,
    skip_parameter_lists: bool,
) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if skip_parameter_lists && node.kind() == "parameter_list" {
            continue;
        }
        if node.kind() == "identifier"
            && node.start_byte() >= after_byte
            && node_text(node, source) == name
            && is_value_reference(node, local)
        {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

/// Whether a local is referenced after its declaration within its lexical
/// block. References in unrelated methods and comments cannot leak in.
pub(crate) fn local_is_referenced(declarator: Node<'_>, name: &str, source: &str) -> bool {
    let Some(scope) = ancestors_of(declarator).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "block" | "switch_body" | "compilation_unit"
        )
    }) else {
        return true;
    };
    mentions_identifier(scope, name, source, declarator.end_byte(), true, false)
}

/// Whether a type/member name has a real reference inside its owning scope.
pub(crate) fn scoped_identifier_is_referenced(scope: Node<'_>, name: &str, source: &str) -> bool {
    let shadowing = shadowing_ranges(scope, name, source);
    let mut pending = vec![scope];
    while let Some(node) = pending.pop() {
        if node.kind() == "identifier"
            && node_text(node, source) == name
            && is_value_reference(node, false)
            && (is_qualified_member_name(node)
                || !shadowing
                    .iter()
                    .any(|range| range.start <= node.start_byte() && node.end_byte() <= range.end))
        {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

/// Whether `root`'s subtree mentions the identifier `name`, ignoring
/// parameter lists (where the parameter itself is declared).
pub(crate) fn mentions_identifier_outside_parameter_list(
    root: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    mentions_identifier(root, name, source, 0, true, true)
}
