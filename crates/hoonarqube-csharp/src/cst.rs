//! Shared concrete-syntax-tree helpers: traversal, text slicing,
//! position mapping, diagnostic construction, and modifier access.

use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

pub(crate) use hoonarqube_ir::u32_saturating as to_u32;

/// Pre-order walk over every named and anonymous child node. A tree cursor
/// avoids both recursion on arbitrarily nested input and a child allocation at
/// every node while preserving exact document order.
pub(crate) fn walk_all<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    let mut cursor = node.walk();
    loop {
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Collects every node whose kind is listed, in document order.
pub(crate) fn collect_kinds<'t>(root: Node<'t>, kinds: &[&str]) -> Vec<Node<'t>> {
    let mut matched = Vec::new();
    walk_all(root, &mut |node| {
        if kinds.contains(&node.kind()) {
            matched.push(node);
        }
    });
    matched
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// C#'s verbatim identifier prefix changes token spelling, not symbol
/// identity (`@value` and `value` bind the same declaration).
pub(crate) fn canonical_identifier(text: &str) -> &str {
    text.strip_prefix('@').unwrap_or(text)
}

/// Maps a tree-sitter point into an IR position. `column` counts characters
/// from the row start, matching this crate's text-scan emitters and the
/// character-based SonarQube/Roslyn text-range convention;
/// `tree_sitter::Point::column` itself is a UTF-8 byte offset within the
/// row and is consumed here only to locate the row-start byte, never
/// emitted directly.
pub(crate) fn pos_of(
    point: tree_sitter::Point,
    byte_offset: usize,
    source: &str,
) -> hoonarqube_ir::Pos {
    let row_start = byte_offset - point.column;
    hoonarqube_ir::Pos {
        line: to_u32(point.row).saturating_add(1),
        column: to_u32(source[row_start..byte_offset].chars().count()),
    }
}

/// Half-open range of `node` with character-based columns
/// (see [`pos_of`]).
pub(crate) fn range_of(node: Node<'_>, source: &str) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: pos_of(node.start_position(), node.start_byte(), source),
        end: pos_of(node.end_position(), node.end_byte(), source),
    }
}

/// Half-open range from UTF-8 byte offsets already known to lie on source
/// boundaries. Text scanners use this to report an exact token inside a
/// larger tree-sitter node.
pub(crate) fn range_from_byte_offsets(
    start: usize,
    end: usize,
    source: &str,
) -> hoonarqube_ir::Range {
    fn advance_position(line: &mut usize, column: &mut usize, text: &str) {
        for character in text.chars() {
            if character == '\n' {
                *line += 1;
                *column = 0;
            } else {
                *column += 1;
            }
        }
    }

    assert!(start <= end, "range start must not exceed its end");
    let before = &source[..start];
    let covered = &source[start..end];
    let mut line = 1;
    let mut column = 0;
    advance_position(&mut line, &mut column, before);
    let start = hoonarqube_ir::Pos {
        line: to_u32(line),
        column: to_u32(column),
    };
    advance_position(&mut line, &mut column, covered);
    let end = hoonarqube_ir::Pos {
        line: to_u32(line),
        column: to_u32(column),
    };

    hoonarqube_ir::Range { start, end }
}

pub(crate) fn issue(
    language: CsLanguage,
    rule: &str,
    message: impl Into<String>,
    range: hoonarqube_ir::Range,
) -> Issue {
    Issue {
        rule_key: format!("{}:{rule}", language.prefix()),
        message: message.into(),
        range,
        fix: None,
    }
}

/// `^[A-Z][a-zA-Z0-9]*$` — `PascalCase` without underscores.
pub(crate) fn is_pascal_case(name: &str) -> bool {
    let mut chars = name.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric())
}

/// Strips a generic or invocation tail (`<…>`, `(…)`) and any qualification,
/// yielding the bare identifier (`System.Exception` / `ILogger<T>` → tail).
pub(crate) fn simple_name(type_text: &str) -> &str {
    let base = type_text.split(['<', '(']).next().unwrap_or(type_text);
    let name = base.rsplit('.').next().unwrap_or(base);
    canonical_identifier(name)
}

/// Evaluates an `csharpsquid:S2342` naming format. Both catalog defaults are
/// understood natively (`PascalCase` words, plural trailing `s` for flags);
/// any custom format degrades to an exact literal match after stripping the
/// `^`/`$` anchors (this analyzer carries no regex engine).
pub(crate) fn matches_enum_format(name: &str, format: &str) -> bool {
    const PLAIN_DEFAULT: &str = "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$";
    const FLAGS_DEFAULT: &str = "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$";
    match format {
        PLAIN_DEFAULT => is_pascal_case(name),
        FLAGS_DEFAULT => is_pascal_case(name) && name.ends_with('s'),
        literal => literal.trim_start_matches('^').trim_end_matches('$') == name,
    }
}

/// Evaluates the `csharpsquid:S6669` logger-name format. The catalog default
/// `^_?[Ll]og(ger)?$` is understood natively; custom formats degrade to an
/// exact literal match after stripping the anchors.
pub(crate) fn matches_logger_format(name: &str, format: &str) -> bool {
    const DEFAULT_FORMAT: &str = "^_?[Ll]og(ger)?$";
    if format != DEFAULT_FORMAT {
        return format.trim_start_matches('^').trim_end_matches('$') == name;
    }
    let bare = name.strip_prefix('_').unwrap_or(name);
    matches!(bare, "log" | "Log" | "logger" | "Logger")
}

/// Modifiers (`public`, `static`, `const`, …) of a declaration, source order.
pub(crate) fn modifiers_of<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "modifier")
        .map(|modifier| node_text(modifier, source))
        .collect()
}

/// Simple names of every base of a type declaration (`class D : B` → `B`),
/// with generic and qualification tails stripped.
pub(crate) fn base_simple_names<'a>(type_node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut cursor = type_node.walk();
    for base_list in type_node
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
    {
        let mut list_cursor = base_list.walk();
        for base in base_list
            .children(&mut list_cursor)
            .filter(tree_sitter::Node::is_named)
        {
            names.push(simple_name(node_text(base, source)));
        }
    }
    names
}

/// Simple attribute names applied directly to `node`
/// (`[OptionalAttribute]` → `Optional`).
pub(crate) fn attributes_of<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    direct_attributes(node)
        .into_iter()
        .filter_map(|attribute| attribute.child_by_field_name("name"))
        .map(|name| {
            let text = simple_name(node_text(name, source));
            text.strip_suffix("Attribute").unwrap_or(text)
        })
        .collect()
}

/// Attribute nodes applied directly to `node`, excluding attributes on nested
/// declarations.
pub(crate) fn direct_attributes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut attributes = Vec::new();
    let mut cursor = node.walk();
    for list in node
        .children(&mut cursor)
        .filter(|child| child.kind() == "attribute_list")
    {
        let mut list_cursor = list.walk();
        for attribute in list
            .children(&mut list_cursor)
            .filter(|child| child.kind() == "attribute")
        {
            attributes.push(attribute);
        }
    }
    attributes
}

/// Parameters of a callable's `parameter_list`.
pub(crate) fn parameters_of(declaration: Node<'_>) -> Vec<Node<'_>> {
    let Some(list) = declaration.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.children(&mut cursor)
        .filter(|child| child.kind() == "parameter")
        .collect()
}

/// Return-type and parameter regions of a callable; scans over these stay
/// out of bodies.
pub(crate) fn signature_regions(declaration: Node<'_>) -> Vec<Node<'_>> {
    ["returns", "type", "parameters"]
        .into_iter()
        .filter_map(|field| declaration.child_by_field_name(field))
        .collect()
}

/// Every parent of `node`, nearest first.
pub(crate) fn ancestors_of(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), tree_sitter::Node::parent)
}

/// Canonical dotted namespace containing `node`; empty for the global
/// namespace. Nested and file-scoped namespace declarations are supported.
pub(crate) fn containing_namespace(node: Node<'_>, source: &str) -> String {
    let mut parts: Vec<&str> = ancestors_of(node)
        .filter(|ancestor| {
            matches!(
                ancestor.kind(),
                "namespace_declaration" | "file_scoped_namespace_declaration"
            )
        })
        .filter_map(|namespace| namespace.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect();
    parts.reverse();
    parts.join(".").replace('@', "")
}

/// True when `node` sits under an `ERROR`/missing region of a recovered
/// tree; such regions carry unreliable structure, so checks skip them.
pub(crate) fn is_error_tainted(node: Node<'_>) -> bool {
    node.is_error() || node.is_missing() || ancestors_of(node).any(|ancestor| ancestor.is_error())
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_identifier, collect_kinds, node_text, pos_of, range_from_byte_offsets, range_of,
        simple_name, walk_all,
    };
    use hoonarqube_ir::{Pos, Range};
    use std::collections::HashSet;

    #[test]
    fn walk_all_is_preorder_without_duplicates() {
        fn recursive_preorder<'tree>(
            node: tree_sitter::Node<'tree>,
            out: &mut Vec<tree_sitter::Node<'tree>>,
        ) {
            out.push(node);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                recursive_preorder(child, out);
            }
        }

        let source = "class C { int M(int x) => x + 1; }";
        let tree = crate::parse(source);
        let root = tree.root_node();
        let mut actual = Vec::new();
        walk_all(root, &mut |node| actual.push(node));

        let mut expected = Vec::new();
        recursive_preorder(root, &mut expected);
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .iter()
                .map(tree_sitter::Node::id)
                .collect::<HashSet<_>>()
                .len(),
            actual.len()
        );
    }

    #[test]
    fn walk_all_handles_deep_trees_iteratively() {
        let source = format!(
            "class C {{ bool M(bool x) => {}x; }}",
            "x && ".repeat(2_000)
        );
        let tree = crate::parse(&source);
        let mut visited = 0;
        walk_all(tree.root_node(), &mut |_| visited += 1);
        assert!(visited > 2_000);
    }

    #[test]
    fn escaped_identifiers_share_their_canonical_symbol_name() {
        assert_eq!(canonical_identifier("@value"), "value");
        assert_eq!(canonical_identifier("value"), "value");
        assert_eq!(simple_name("System.@Exception"), "Exception");
    }

    #[test]
    fn byte_ranges_count_unicode_scalars_and_crlf_lines() {
        let source = "class C {\r\n    string s = \"😀\";\n    int café;\n}\n";
        let emoji_start = source.find('😀').expect("emoji offset");
        assert_eq!(
            range_from_byte_offsets(emoji_start, emoji_start + '😀'.len_utf8(), source),
            Range {
                start: Pos {
                    line: 2,
                    column: 16,
                },
                end: Pos {
                    line: 2,
                    column: 17,
                },
            }
        );
        let identifier_end = source.find("café").expect("identifier offset") + "café".len();
        assert_eq!(
            range_from_byte_offsets(emoji_start, identifier_end, source),
            Range {
                start: Pos {
                    line: 2,
                    column: 16,
                },
                end: Pos {
                    line: 3,
                    column: 12,
                },
            }
        );

        let tree = crate::parse(source);
        let identifier = collect_kinds(tree.root_node(), &["identifier"])
            .into_iter()
            .find(|node| node_text(*node, source) == "café")
            .expect("unicode identifier");
        assert_eq!(
            range_of(identifier, source),
            Range {
                start: Pos { line: 3, column: 8 },
                end: Pos {
                    line: 3,
                    column: 12,
                },
            }
        );
    }

    #[test]
    fn position_line_conversion_saturates() {
        assert_eq!(
            pos_of(tree_sitter::Point::new(usize::MAX, 0), 0, ""),
            Pos {
                line: u32::MAX,
                column: 0,
            }
        );
    }
}
