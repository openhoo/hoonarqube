use crate::AnalyzerOptions;
use crate::support::comment_tokens;
use crate::support::issue_at;
use crate::support::legal_trailing_comment;
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
