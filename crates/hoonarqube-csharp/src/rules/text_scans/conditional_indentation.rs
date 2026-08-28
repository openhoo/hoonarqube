use crate::CsLanguage;
use crate::cst::{issue, pos_of, range_from_byte_offsets, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3973 — conditionally executed single lines must be denoted by
/// indentation: a brace-less body on its own line may not start at or before
/// its header's column.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !CONDITIONAL_HEADER_KINDS.contains(&node.kind()) {
            return;
        }
        let header_pos = pos_of(node.start_position(), node.start_byte(), source);
        let mut bodies: Vec<Node> = Vec::new();
        if node.kind() == "if_statement" {
            if let Some(consequence) = node.child_by_field_name("consequence") {
                bodies.push(consequence);
            }
            // An `else if(...)` chain link keeps its own header position.
            if let Some(alternative) = node.child_by_field_name("alternative")
                && alternative.kind() != "if_statement"
            {
                bodies.push(alternative);
            }
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named()
                    && child.kind() != "block"
                    && child.kind().ends_with("_statement")
                {
                    bodies.push(child);
                }
            }
        }
        for body in bodies {
            let body_pos = pos_of(body.start_position(), body.start_byte(), source);
            if body_pos.line > header_pos.line && body_pos.column <= header_pos.column {
                let header_end = node
                    .child_by_field_name("condition")
                    .and_then(|condition| {
                        source[condition.end_byte()..node.end_byte()]
                            .find(')')
                            .map(|offset| condition.end_byte() + offset + 1)
                    })
                    .unwrap_or(body.start_byte());
                let keyword = node.kind().trim_end_matches("_statement");
                issues.push(issue(
                    language,
                    "S3973",
                    format!(
                        "Use curly braces or indentation to denote the code conditionally executed by this '{keyword}'"
                    ),
                    range_from_byte_offsets(node.start_byte(), header_end, source),
                ));
            }
        }
    });
    issues
}

/// Headers with brace-less single-statement bodies (`if`, loops, `using`,
/// `lock`, `fixed`).
const CONDITIONAL_HEADER_KINDS: [&str; 7] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];
