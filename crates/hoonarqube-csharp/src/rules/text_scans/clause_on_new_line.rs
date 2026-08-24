use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3972 — `else`, `catch`, and `finally` start on a new line.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let keyword_kinds: &[&str] = match node.kind() {
            "if_statement" => &["else"],
            "try_statement" => &["catch_clause", "finally_clause"],
            _ => return,
        };
        let mut cursor = node.walk();
        let mut previous_end_row: Option<usize> = None;
        for child in node.children(&mut cursor) {
            if keyword_kinds.contains(&child.kind())
                && previous_end_row == Some(child.start_position().row)
            {
                let keyword = child.kind().strip_suffix("_clause").unwrap_or(child.kind());
                issues.push(issue(
                    language,
                    "S3972",
                    format!("Move this \"{keyword}\" to a new line."),
                    range_of(child),
                ));
            }
            previous_end_row = Some(child.end_position().row);
        }
    });
    issues
}
