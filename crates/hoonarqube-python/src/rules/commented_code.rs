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

/// The frozen catalog declares parameter `exception = "(fmt|py\w+):.*"` for
/// python:S125. Custom values are not surfaced through `AnalyzerOptions`, so
/// the default shape is pinned here: comments whose text starts with `fmt:`
/// or `py<word>:` are tool markers, not commented-out code.
fn matches_catalog_exception(line: &str) -> bool {
    let content = line.trim_start();
    let Some(content) = content.strip_prefix('#') else {
        return false;
    };
    let content = content.trim_start();
    if content.starts_with("fmt:") {
        return true;
    }
    let Some(rest) = content.strip_prefix("py") else {
        return false;
    };
    let word = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    word > 0 && rest[word..].starts_with(':')
}

pub(crate) fn check_commented_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for token in comment_tokens(parsed) {
        let looks_like_code = source[token.range()]
            .lines()
            .filter(|line| !matches_catalog_exception(line))
            .any(line_looks_like_code);
        if looks_like_code {
            issues.push(Issue {
                rule_key: "python:S125".to_string(),
                message: "Remove this commented out code.".to_string(),
                range: to_range(token.range(), index, source),
                fix: None,
            });
        }
    }
    issues
}
