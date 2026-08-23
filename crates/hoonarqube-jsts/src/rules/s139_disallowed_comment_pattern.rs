// Rule module s139_disallowed_comment_pattern (generated).

use hoonarqube_ir::{Issue};
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{regex_search};
use crate::support::{IssueSink, RuleScope, ScannedComment, line_start, scan_comments, source_slice};


/// `S139`: a comment on a line that also carries code, matching the
/// configured `pattern` (default `^\s*[^\s]+$`).
pub(crate) fn check_disallowed_comment_pattern(
    sink: &mut IssueSink,
    source: &str,
    comment: ScannedComment,
    body: &str,
    rules: &RuleOptions,
) {
    let line_start = comment.token.start - sink.index.pos(comment.token.start).column;
    let code_before = source
        .get(
            usize::try_from(line_start).unwrap_or(0)
                ..usize::try_from(comment.token.start).unwrap_or(0),
        )
        .is_some_and(|prefix| prefix.chars().any(|c| !c.is_whitespace()));
    if !code_before || !regex_search(&rules.comment_pattern, body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S139",
        "Rewrite or remove this comment; it matches the configured disallowed pattern.",
        comment.token,
    );
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for comment in scan_comments(ctx.source) {
        let body = source_slice(ctx.source, comment.body);
        check_disallowed_comment_pattern(&mut sink, ctx.source, comment, body, ctx.rules);
    }
    sink.issues
}
