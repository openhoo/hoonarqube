use crate::support::comment_tokens;
use crate::support::line_looks_like_code;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// ---------------------------------------------------------------------------
// python:S125 — commented-out code.
// ---------------------------------------------------------------------------

pub(crate) fn check_commented_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for token in comment_tokens(parsed) {
        if source[token.range()].lines().any(line_looks_like_code) {
            issues.push(Issue {
                rule_key: "python:S125".to_string(),
                message: "Remove this commented-out code.".to_string(),
                range: to_range(token.range(), index, source),
            });
        }
    }
    issues
}
