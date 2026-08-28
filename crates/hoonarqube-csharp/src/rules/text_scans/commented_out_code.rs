use super::support::CODE_KEYWORDS;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S125 — sections of code should not be commented out. Flags
/// runs of consecutive line comments (never `///` documentation) in which at
/// least one line is code-like.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut line_comments: Vec<Node> = Vec::new();
    walk_all(root, &mut |node| {
        let text = node_text(node, source);
        if node.kind() == "comment" && text.starts_with("//") && !text.starts_with("///") {
            line_comments.push(node);
        }
    });
    let mut issues = Vec::new();
    let mut run_start: Option<Node> = None;
    let mut run_has_code = false;
    let mut expected_next_row: Option<usize> = None;
    for comment in line_comments {
        if expected_next_row != Some(comment.start_position().row) {
            if run_has_code {
                push_commented_out_code(&mut issues, language, run_start, source);
            }
            run_start = Some(comment);
            run_has_code = false;
        }
        run_has_code |= looks_like_code(node_text(comment, source).trim_start_matches('/'));
        expected_next_row = Some(comment.end_position().row + 1);
    }
    if run_has_code {
        push_commented_out_code(&mut issues, language, run_start, source);
    }
    issues
}

/// Heuristic: does this stripped comment line look like commented-out code?
fn looks_like_code(line: &str) -> bool {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return false;
    }
    let keyword_led = CODE_KEYWORDS.iter().any(|keyword| {
        trimmed.starts_with(keyword)
            && trimmed[keyword.len()..]
                .starts_with(|c: char| c.is_whitespace() || "({;=\"'<+".contains(c))
    });
    let statement_shaped = (trimmed.ends_with(';')
        && (trimmed.contains('(') || trimmed.contains('=')))
        || trimmed.ends_with('{')
        || trimmed.ends_with('}');
    statement_shaped || (keyword_led && (trimmed.contains(';') || trimmed.contains('(')))
}

/// Anchors an S125 issue at the start of a code-like comment run.
fn push_commented_out_code(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    start: Option<Node>,
    source: &str,
) {
    let Some(start) = start else {
        return;
    };
    issues.push(issue(
        language,
        "S125",
        "Remove this commented out code.",
        range_of(start, source),
    ));
}
