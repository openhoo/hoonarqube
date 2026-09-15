use crate::CsLanguage;
use crate::cst::{issue, pos_of, range_from_byte_offsets, walk_all};
use hoonarqube_ir::{Issue, Pos};
use tree_sitter::Node;

/// csharpsquid:S3973 — conditionally executed single lines must be denoted by
/// indentation: a brace-less body on its own line may not start at or before
/// its header's column. Braced bodies are always denoted by braces, so blocks
/// never qualify, and `else` bodies and `else if` chain links are judged
/// against their own `else` keyword rather than the chain's first header.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !CONDITIONAL_HEADER_KINDS.contains(&node.kind()) {
            return;
        }
        let mut header_pos = pos_of(node.start_position(), node.start_byte(), source);
        if node.kind() == "if_statement" {
            // An `else if(...)` chain link keeps its own header position: the
            // reference rule measures it against the `else` keyword.
            if let Some(else_pos) = link_else_keyword_pos(node, source) {
                header_pos = else_pos;
            }
            if let Some(consequence) = node.child_by_field_name("consequence") {
                report_body(&mut issues, node, consequence, header_pos, source, language);
            }
            if let Some(alternative) = node.child_by_field_name("alternative")
                && alternative.kind() != "if_statement"
            {
                let alternative_header =
                    else_keyword_pos(node, alternative, source).unwrap_or(header_pos);
                report_body(
                    &mut issues,
                    node,
                    alternative,
                    alternative_header,
                    source,
                    language,
                );
            }
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named()
                    && child.kind() != "block"
                    && child.kind().ends_with("_statement")
                {
                    report_body(&mut issues, node, child, header_pos, source, language);
                }
            }
        }
    });
    issues
}

fn report_body(
    issues: &mut Vec<Issue>,
    header: Node<'_>,
    body: Node<'_>,
    header_pos: Pos,
    source: &str,
    language: CsLanguage,
) {
    // A braced body is denoted by braces; only a bare statement can be
    // misleadingly indented.
    if body.kind() == "block" {
        return;
    }
    let body_pos = pos_of(body.start_position(), body.start_byte(), source);
    if body_pos.line <= header_pos.line || body_pos.column > header_pos.column {
        return;
    }
    let header_end = header
        .child_by_field_name("condition")
        .and_then(|condition| {
            source[condition.end_byte()..header.end_byte()]
                .find(')')
                .map(|offset| condition.end_byte() + offset + 1)
        })
        .unwrap_or(body.start_byte());
    let keyword = header.kind().trim_end_matches("_statement");
    issues.push(issue(
        language,
        "S3973",
        format!(
            "Use curly braces or indentation to denote the code conditionally executed by this '{keyword}'"
        ),
        range_from_byte_offsets(header.start_byte(), header_end, source),
    ));
}

/// Position of the `else` keyword introducing `node`, when `node` is an
/// `else if` chain link of an enclosing `if_statement`.
fn link_else_keyword_pos(node: Node<'_>, source: &str) -> Option<Pos> {
    let parent = node
        .parent()
        .filter(|parent| parent.kind() == "if_statement")?;
    let alternative = parent.child_by_field_name("alternative")?;
    (alternative.id() == node.id())
        .then(|| else_keyword_pos(parent, node, source))
        .flatten()
}

/// Position of the `else` keyword introducing `alternative` inside `owner`.
fn else_keyword_pos(owner: Node<'_>, alternative: Node<'_>, source: &str) -> Option<Pos> {
    let offset =
        source[owner.start_byte()..alternative.start_byte()].rfind("else")? + owner.start_byte();
    let prefix = &source[..offset];
    let mut lines = prefix.split('\n');
    let column =
        u32::try_from(lines.next_back().unwrap_or_default().chars().count()).unwrap_or(u32::MAX);
    Some(Pos {
        line: u32::try_from(lines.count())
            .unwrap_or(u32::MAX)
            .saturating_add(1),
        column,
    })
}

/// Headers with brace-less single-statement bodies (`if`, `do`, and the
/// loop headers) — the reference rule's checked statement kinds.
const CONDITIONAL_HEADER_KINDS: [&str; 5] = [
    "if_statement",
    "do_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
];
