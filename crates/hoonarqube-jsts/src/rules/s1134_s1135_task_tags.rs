// Rule module s1134_s1135_task_tags (generated).

use hoonarqube_ir::{Issue};
use oxc_span::{Span};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope, ScannedComment, scan_comments, source_slice, to_u32};


/// `S1134` (FIXME) and `S1135` (TODO) task tags.
pub(crate) fn check_flagged_tags(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    for (tag, rule, message) in [
        (
            "FIXME",
            "S1134",
            "Complete the work corresponding to this \"FIXME\" comment.",
        ),
        (
            "TODO",
            "S1135",
            "Complete the task associated to this \"TODO\" comment.",
        ),
    ] {
        if let Some(offset) = find_tag(body, tag) {
            let start = comment.body.start + to_u32(offset);
            sink.emit_span(
                RuleScope::Both,
                rule,
                message,
                Span::new(start, start + to_u32(tag.len())),
            );
        }
    }
}


/// First whole-word occurrence of `tag` in a comment body.
pub(crate) fn find_tag(body: &str, tag: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut search_from = 0;
    while let Some(relative) = body[search_from..].find(tag) {
        let start = search_from + relative;
        let end = start + tag.len();
        let word_start = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let word_end = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if word_start && word_end {
            return Some(start);
        }
        search_from = end;
    }
    None
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for comment in scan_comments(ctx.source) {
        let body = source_slice(ctx.source, comment.body);
        check_flagged_tags(&mut sink, comment, body);
    }
    sink.issues
}
