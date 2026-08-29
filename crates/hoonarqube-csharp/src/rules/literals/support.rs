use crate::cst::{canonical_identifier, collect_kinds, node_text, simple_name};
use tree_sitter::Node;

/// Every plain, verbatim, and raw string literal in the file, document
/// order. Interpolated strings carry no static content and are skipped.
pub(crate) fn string_literals(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(
        root,
        &[
            "string_literal",
            "verbatim_string_literal",
            "raw_string_literal",
        ],
    )
}

pub(crate) fn is_string_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string_literal" | "verbatim_string_literal" | "raw_string_literal"
    )
}

/// Inner text of a plain, verbatim, or raw string literal: quotes and the
/// verbatim `@` prefix stripped; escape sequences stay as written. Raw
/// strings lose their opening and closing quote runs; multi-line raw
/// strings keep their source indentation (the compiler strips it at
/// runtime), which never changes regex validation or secret heuristics.
pub(crate) fn literal_inner_text<'a>(literal: Node<'_>, source: &'a str) -> &'a str {
    let text = node_text(literal, source);
    let trimmed = text.trim_start_matches('@');
    let leading = trimmed.chars().take_while(|char| *char == '"').count();
    if leading >= 3 {
        // Raw string: strip both delimiter quote runs. Content cannot
        // repeat the delimiter, so the shorter run bounds the literal;
        // `get` keeps degenerate inputs panic-free.
        let trailing = trimmed
            .chars()
            .rev()
            .take_while(|char| *char == '"')
            .count();
        let quotes = leading.min(trailing);
        return trimmed.get(quotes..trimmed.len() - quotes).unwrap_or("");
    }
    trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(trimmed)
}

/// Byte offset of [`literal_inner_text`] relative to the literal node. This
/// keeps diagnostics exact for plain, verbatim, and variable-width raw-string
/// delimiters.
pub(crate) fn literal_inner_offset(literal: Node<'_>, source: &str) -> usize {
    let text = node_text(literal, source);
    let trimmed = text.trim_start_matches('@');
    let prefix = text.len() - trimmed.len();
    let quotes = trimmed
        .chars()
        .take_while(|character| *character == '"')
        .count();
    prefix
        + if quotes >= 3 {
            quotes
        } else {
            usize::from(trimmed.starts_with('"'))
        }
}

/// Simple name of an assignment target: bare identifiers and the trailing
/// member of `this.Password`-style accesses.
pub(crate) fn assignment_target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(canonical_identifier(node_text(target, source))),
        "member_access_expression" => {
            let name = target.child_by_field_name("name")?;
            Some(canonical_identifier(node_text(name, source)))
        }
        _ => None,
    }
}

/// The initializer of a declarator, if any: its last named child behind the
/// name (`x = "v"`).
pub(crate) fn declarator_initializer<'a>(declarator: Node<'a>, name: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = declarator.walk();
    declarator
        .named_children(&mut cursor)
        .find(|child| child.id() != name.id())
}

/// Every place where a named target receives a string literal: assignments
/// (`password = "x"`) and declarator initializers (`var key = "x";`). Yields
/// `(anchor, target name, literal)` triples in document order.
pub(crate) fn literal_assignments<'t, 's>(
    root: Node<'t>,
    source: &'s str,
) -> Vec<(Node<'t>, &'s str, Node<'t>)> {
    let mut out = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if is_string_literal(right)
            && let Some(name) = assignment_target_name(left, source)
        {
            out.push((assignment, name, right));
        }
    }
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(initializer) = declarator_initializer(declarator, name) else {
            continue;
        };
        if is_string_literal(initializer) {
            out.push((declarator, node_text(name, source), initializer));
        }
    }
    out
}

pub(crate) fn argument_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "argument")
        .collect()
}

/// The expression inside an `argument` wrapper node.
pub(crate) fn argument_expression(argument: Node<'_>) -> Node<'_> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .next()
        .unwrap_or(argument)
}

/// Whether an object creation instantiates `Regex` directly.
pub(crate) fn is_regex_creation(creation: Node<'_>, source: &str) -> bool {
    creation
        .child_by_field_name("type")
        .is_none_or(|type_node| simple_name(node_text(type_node, source)) != "Regex")
        .then_some(())
        .is_none()
}

/// Methods of `System.Text.RegularExpressions.Regex` taking a pattern.
const REGEX_PATTERN_METHODS: [&str; 5] = ["IsMatch", "Match", "Matches", "Replace", "Split"];

/// The pattern argument of a static `Regex.Method(...)` call, if any.
pub(crate) fn regex_static_pattern<'t>(invocation: Node<'t>, source: &str) -> Option<Node<'t>> {
    let function = invocation.child_by_field_name("function")?;
    if function.kind() != "member_access_expression" {
        return None;
    }
    let receiver = function.child_by_field_name("expression")?;
    let name = function.child_by_field_name("name")?;
    if simple_name(node_text(receiver, source)) != "Regex"
        || !REGEX_PATTERN_METHODS.contains(&node_text(name, source))
    {
        return None;
    }
    let arguments = invocation.child_by_field_name("arguments")?;
    argument_nodes(arguments)
        .get(1)
        .copied()
        .map(argument_expression)
}
