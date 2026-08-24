// Rule module s1291_nosonar (generated).

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, ScannedComment, scan_comments, source_slice};
use hoonarqube_ir::Issue;

/// `S1291`: the `NOSONAR` suppression marker.
pub(crate) fn check_nosonar(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    if body.contains("NOSONAR") {
        sink.emit_span(
            RuleScope::Both,
            "S1291",
            "Remove this \"NOSONAR\" comment and fix the suppressed issue.",
            comment.token,
        );
    }
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for comment in scan_comments(ctx.source) {
        let body = source_slice(ctx.source, comment.body);
        check_nosonar(&mut sink, comment, body);
    }
    sink.issues
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn nosonar_marker_in_comments_is_flagged() {
        let line = js_keys("// workaround NOSONAR\nlet a = 1;\n");
        assert_eq!(count_key(&line, "javascript:S1291"), 1);

        let block = js_keys("/* NOSONAR */\nlet a = 1;\n");
        assert_eq!(count_key(&block, "javascript:S1291"), 1);
    }

    #[test]
    fn nosonar_match_is_case_sensitive() {
        let lower = js_keys("// nosonar please\nlet a = 1;\n");
        assert_eq!(count_key(&lower, "javascript:S1291"), 0);
    }
}
