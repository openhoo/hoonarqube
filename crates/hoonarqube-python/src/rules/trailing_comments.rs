use crate::AnalyzerOptions;
use crate::support::comment_tokens;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_trailing_comments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for token in comment_tokens(parsed) {
        let raw = &source[token.range()];
        if !raw.starts_with('#') {
            continue;
        }
        let offset = u32::from(token.range().start()) as usize;
        let line_start = source[..offset]
            .rfind('\n')
            .map_or(0, |position| position + 1);
        let code_before_comment = !source[line_start..offset].trim().is_empty();
        let content = raw[1..].trim();
        // A line already carrying the NOSONAR marker is handled by the
        // dedicated suppression rule; do not double-report it.
        if code_before_comment
            && !raw.contains("NOSONAR")
            && !legal_trailing_comment(&options.legal_trailing_comment_pattern, content)
        {
            issues.push(issue_at(
                "python:S139",
                "Move this trailing comment to its own line.",
                token.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S139 — comments at the end of code lines -----------------------------------

/// Default catalog semantics: `fmt:`/`type:`/`noqa:` directives and
/// single-token comments are legal; arbitrary user patterns are matched
/// naively (`prefix.*`, `\S+`-style alternatives, literals).
fn legal_trailing_comment(pattern: &str, content: &str) -> bool {
    if pattern.is_empty() {
        return !content.is_empty()
            && (!content.contains(char::is_whitespace)
                || content.starts_with("fmt:")
                || content.starts_with("type:")
                || content.starts_with("noqa"));
    }
    pattern.split('|').any(|alternative| {
        let alternative = alternative.trim_matches('^').trim_matches('$');
        if alternative.ends_with(".*") {
            content.starts_with(alternative.trim_end_matches(".*"))
        } else if matches!(alternative, "[^\\s]++" | "\\S+" | "[^\\s]+") {
            !content.is_empty() && !content.contains(char::is_whitespace)
        } else {
            content == alternative
        }
    })
}
