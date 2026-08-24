use crate::cst::{attributes_of, collect_kinds, node_text};
use crate::rules::naming::type_members;
use tree_sitter::Node;

/// Headers embedding a brace-less statement body.
pub(crate) const EMBEDDED_HEADER_KINDS: [&str; 8] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];

/// Declarations whose `block` children are callable bodies.
pub(crate) const CALLABLE_BODY_OWNER_KINDS: [&str; 6] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
];

/// True for nodes forming statements: explicit `block`s and `*_statement`s.
pub(crate) fn is_statement_kind(kind: &str) -> bool {
    kind == "block" || kind.ends_with("_statement")
}

/// Statement bodies embedded in a control header, source order: the
/// consequence first, the `else` alternative last.
pub(crate) fn embedded_bodies(header: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = header.walk();
    header
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// The statement following an `else` keyword, when present.
pub(crate) fn else_alternative(if_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = if_statement.walk();
    let mut past_else = false;
    for child in if_statement.children(&mut cursor) {
        if child.kind() == "else" {
            past_else = true;
        } else if past_else && child.is_named() {
            return Some(child);
        }
    }
    None
}

/// Whether `node` is the alternative branch of an enclosing `if_statement`.
pub(crate) fn is_else_alternative(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "if_statement" && else_alternative(parent) == Some(node)
    })
}

/// The `switch_body` of a `switch_statement`.
pub(crate) fn switch_body_of(switch_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = switch_statement.walk();
    switch_statement
        .children(&mut cursor)
        .find(|child| child.kind() == "switch_body")
}

/// Sections of a `switch_body`, source order.
pub(crate) fn switch_sections_of(switch_body: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = switch_body.walk();
    switch_body
        .children(&mut cursor)
        .filter(|child| child.kind() == "switch_section")
        .collect()
}

/// Whether a section carries a `default` label.
pub(crate) fn section_has_default(section: Node<'_>) -> bool {
    let mut cursor = section.walk();
    section
        .children(&mut cursor)
        .any(|child| child.kind() == "default")
}

/// Statements directly inside a section; labels are anonymous tokens and
/// never appear here.
pub(crate) fn section_statements(section: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = section.walk();
    section
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// The initializer, condition, and update clauses of a `for_statement`,
/// split on its semicolons.
pub(crate) fn for_clauses(
    for_statement: Node<'_>,
) -> (Option<Node<'_>>, Option<Node<'_>>, Option<Node<'_>>) {
    let mut clauses = [None, None, None];
    let mut semicolons_seen = 0_usize;
    let mut cursor = for_statement.walk();
    for child in for_statement.children(&mut cursor) {
        if child.kind() == ")" {
            break;
        }
        if child.kind() == ";" {
            semicolons_seen += 1;
        } else if child.is_named() && semicolons_seen < clauses.len() {
            clauses[semicolons_seen] = Some(child);
        }
    }
    (clauses[0], clauses[1], clauses[2])
}

/// Loop-counter candidate of an initializer clause: its first identifier
/// (`int i = 0`, `i = 0`, both spellings alike).
pub(crate) fn counter_name<'a>(initializer: Node<'_>, source: &'a str) -> Option<&'a str> {
    collect_kinds(initializer, &["identifier"])
        .first()
        .map(|identifier| node_text(*identifier, source))
}

/// The `block` body of a callable, when it has one (abstract and
/// expression-bodied members do not).
pub(crate) fn body_of(declaration: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "block")
}

/// A declaration's name identifier, falling back to the whole declaration.
pub(crate) fn name_anchor(declaration: Node<'_>) -> Node<'_> {
    declaration
        .child_by_field_name("name")
        .unwrap_or(declaration)
}

/// Whether the declaration carries any attribute directly.
pub(crate) fn is_attributed(declaration: Node<'_>, source: &str) -> bool {
    !attributes_of(declaration, source).is_empty()
}

/// The operator token of a binary expression (`&&`, `<<`, `==`, ...).
pub(crate) fn binary_operator<'a>(expression: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = expression.walk();
    expression
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map_or("", |token| node_text(token, source))
}

/// Accessors of a property's accessor list, source order.
pub(crate) fn accessors_of(property: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = property.walk();
    property
        .children(&mut cursor)
        .find(|child| child.kind() == "accessor_list")
        .map(|list| {
            let mut list_cursor = list.walk();
            list.children(&mut list_cursor)
                .filter(|accessor| accessor.kind() == "accessor_declaration")
                .collect()
        })
        .unwrap_or_default()
}

/// An accessor's keyword (`get`, `set`, ...).
pub(crate) fn accessor_keyword<'a>(accessor: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = accessor.walk();
    accessor
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map_or("", |token| node_text(token, source))
}

/// The backing identifier a getter yields: a lone `return field;` or
/// `=> field;` body. Computed returns (`return field + 1;`) never match.
pub(crate) fn getter_field<'a>(accessor: Node<'_>, source: &'a str) -> Option<&'a str> {
    fn yields_sole_identifier(expression: Node<'_>) -> bool {
        let mut cursor = expression.walk();
        let operands: Vec<Node> = expression
            .children(&mut cursor)
            .filter(tree_sitter::Node::is_named)
            .collect();
        operands.len() == 1 && operands[0].kind() == "identifier"
    }
    let body = body_of(accessor)?;
    let shaped = if body.kind() == "arrow_expression_clause" {
        yields_sole_identifier(body)
    } else if body.kind() == "block" {
        let statements = embedded_bodies(body);
        statements.len() == 1
            && statements[0].kind() == "return_statement"
            && yields_sole_identifier(statements[0])
    } else {
        false
    };
    if !shaped {
        return None;
    }
    let identifiers = collect_kinds(body, &["identifier"]);
    (identifiers.len() == 1).then(|| node_text(identifiers[0], source))
}

/// The backing identifier a setter stores into: a single `field = value;`
/// or `=> field = value;` body.
pub(crate) fn setter_field<'a>(accessor: Node<'_>, source: &'a str) -> Option<&'a str> {
    let body = body_of(accessor)?;
    let assignments = collect_kinds(body, &["assignment_expression"]);
    let assignment = assignments.first()?;
    let identifiers = collect_kinds(*assignment, &["identifier"]);
    if assignments.len() != 1
        || identifiers.len() != 2
        || binary_operator(*assignment, source) != "="
        || node_text(identifiers[1], source) != "value"
    {
        return None;
    }
    Some(node_text(identifiers[0], source))
}

/// Whether a type's declaration list carries no member declarations; the
/// raw member list includes the anonymous braces.
pub(crate) fn type_has_no_members(type_node: Node<'_>) -> bool {
    type_members(type_node)
        .iter()
        .all(|member| !member.is_named())
}
