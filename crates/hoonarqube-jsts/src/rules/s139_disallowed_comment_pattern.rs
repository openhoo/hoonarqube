// Rule module s139_disallowed_comment_pattern (generated).

use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::regex_search;
use crate::support::{IssueSink, RuleScope, ScannedComment, scan_comments, source_slice};
use hoonarqube_ir::Issue;

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn disallowed_comment_pattern_only_fires_on_code_lines() {
        let inline = js_keys("let x = 1; // hack\n");
        assert_eq!(count_key(&inline, "javascript:S139"), 1);

        let own_line = js_keys("// hack\nlet x = 1;\n");
        assert_eq!(count_key(&own_line, "javascript:S139"), 0);
    }
    #[test]
    fn custom_pattern_applies_to_inline_comments_only() {
        let rules = RuleOptions {
            comment_pattern: "TODO".to_string(),
            ..RuleOptions::default()
        };
        let inline = keys_with_rules("let a = 1; // TODO reconsider\n", &rules);
        assert_eq!(count_key(&inline, "javascript:S139"), 1);

        let own_line = keys_with_rules("// TODO reconsider\nlet a = 1;\n", &rules);
        assert_eq!(count_key(&own_line, "javascript:S139"), 0);
    }

    #[test]
    fn whitespace_only_inline_comment_is_allowed_by_default_pattern() {
        let findings = js_keys("let a = 1; //   \n");
        assert_eq!(count_key(&findings, "javascript:S139"), 0);
    }
}
