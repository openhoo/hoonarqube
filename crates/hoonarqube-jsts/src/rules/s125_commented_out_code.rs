// Rule module s125_commented_out_code (generated).

use hoonarqube_ir::{Issue};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope, ScannedComment, scan_comments, source_slice};


/// `S125`: heuristics for comments that look like commented-out code:
/// statement keyword starts, a trailing `;` with an assignment or call, or
/// balanced non-empty braces plus a `;`.
pub(crate) fn check_commented_out_code(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
    if !looks_like_code(body) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S125",
        "Remove this commented-out code.",
        comment.token,
    );
}


pub(crate) fn looks_like_code(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.len() < 4
        || ["TODO", "FIXME", "NOSONAR"]
            .iter()
            .any(|tag| trimmed.contains(tag))
    {
        return false;
    }
    let first_word = trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
        .find(|word| !word.is_empty());
    if first_word.is_some_and(|word| CODE_START_KEYWORDS.contains(&word)) {
        return true;
    }
    if trimmed.ends_with(';') && (trimmed.contains('=') || trimmed.contains('(')) {
        return true;
    }
    trimmed.matches('{').count() == trimmed.matches('}').count()
        && trimmed.contains('{')
        && trimmed.contains(';')
}


/// Keywords whose comment prefix suggests commented-out code for `S125`.
pub(crate) const CODE_START_KEYWORDS: [&str; 11] = [
    "if", "for", "while", "switch", "var", "let", "const", "function", "return", "import", "export",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for comment in scan_comments(ctx.source) {
        let body = source_slice(ctx.source, comment.body);
        check_commented_out_code(&mut sink, comment, body);
    }
    sink.issues
}
