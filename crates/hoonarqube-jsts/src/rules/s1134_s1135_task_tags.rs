// Rule module s1134_s1135_task_tags (generated).

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, ScannedComment, source_slice, to_u32};
use hoonarqube_ir::Issue;
use oxc_span::Span;

/// `S1134` (FIXME) and `S1135` (TODO) task tags.
fn check_flagged_tags(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    for (tag, rule, message) in [
        (
            "FIXME",
            "S1134",
            "Take the required action to fix the issue indicated by this comment.",
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
fn find_tag(body: &str, tag: &str) -> Option<usize> {
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
    for &comment in &ctx.comments {
        let body = source_slice(ctx.source, comment.body);
        check_flagged_tags(&mut sink, comment, body);
    }
    sink.issues
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn todo_tags_report_s1135() {
        let findings = js_keys("// TODO implement this\nlet a = 1;\n");
        assert_eq!(count_key(&findings, "javascript:S1135"), 1);
    }

    #[test]
    fn fixme_tags_report_s1134() {
        let findings = js_keys("// FIXME crash on empty input\nlet a = 1;\n");
        assert_eq!(count_key(&findings, "javascript:S1134"), 1);
    }

    #[test]
    fn mixed_tag_comment_reports_both_rules() {
        let findings = js_keys("// TODO and FIXME in one note\nlet a = 1;\n");
        assert_eq!(count_key(&findings, "javascript:S1135"), 1);
        assert_eq!(count_key(&findings, "javascript:S1134"), 1);
    }

    #[test]
    fn tags_inside_longer_words_or_lowercase_stay_silent() {
        let todos = js_keys("// TODOS live elsewhere\nlet a = 1;\n");
        assert_eq!(count_key(&todos, "javascript:S1135"), 0);

        let lower = js_keys("// todo: lowercase stays silent\nlet a = 1;\n");
        assert_eq!(count_key(&lower, "javascript:S1135"), 0);
    }
}
