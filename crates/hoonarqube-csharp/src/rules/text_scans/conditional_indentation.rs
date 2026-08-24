use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3973 — conditionally executed single lines must be denoted by
/// indentation: a brace-less body on its own line may not start at or before
/// its header's column.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !CONDITIONAL_HEADER_KINDS.contains(&node.kind()) {
            return;
        }
        let header = node.start_position();
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
            let start = body.start_position();
            if start.row > header.row && start.column <= header.column {
                issues.push(issue(
                    language,
                    "S3973",
                    "Indent this statement to make its scope obvious.",
                    range_of(body),
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
