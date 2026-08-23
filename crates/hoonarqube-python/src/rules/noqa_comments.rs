use crate::support::comment_tokens;
use crate::support::noqa_format_valid;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1309 — any `noqa` suppression comment is tracked.
/// python:S7632 — `noqa` comments must use `# noqa: CODE[,CODE...]` with
/// uppercase letter+digit codes.
pub(crate) fn check_noqa_comments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let text = &source[comment.range()];
        if !text.to_lowercase().contains("noqa") {
            continue;
        }
        issues.push(Issue {
            rule_key: "python:S1309".to_string(),
            message: "Do not suppress issues with a 'noqa' comment; fix the issue instead."
                .to_string(),
            range: to_range(comment.range(), index, source),
        });
        if !noqa_format_valid(text) {
            issues.push(Issue {
                rule_key: "python:S7632".to_string(),
                message: "Use the format '# noqa: CODE' with comma-separated uppercase codes."
                    .to_string(),
                range: to_range(comment.range(), index, source),
            });
        }
    }
    issues
}
