// Rule module s1291_nosonar (generated).

use hoonarqube_ir::{Issue};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope, ScannedComment, scan_comments, source_slice};


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
