// Rule module s125_commented_out_code (generated).

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, ScannedComment, source_slice};
use hoonarqube_ir::Issue;

/// `S125`: heuristics for comments that look like commented-out code:
/// statement keyword starts, a trailing `;` with an assignment or call, or
/// balanced non-empty braces plus a `;`.
fn check_commented_out_code(sink: &mut IssueSink, comment: ScannedComment, body: &str) {
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

fn looks_like_code(body: &str) -> bool {
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
const CODE_START_KEYWORDS: [&str; 11] = [
    "if", "for", "while", "switch", "var", "let", "const", "function", "return", "import", "export",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    for &comment in &ctx.comments {
        let body = source_slice(ctx.source, comment.body);
        check_commented_out_code(&mut sink, comment, body);
    }
    sink.issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn commented_out_code_heuristic_flags_keyword_comments() {
        let flagged = js_keys("// return value;\n");
        assert_eq!(count_key(&flagged, "javascript:S125"), 1);

        let prose = js_keys("// this comment only explains things\n");
        assert_eq!(count_key(&prose, "javascript:S125"), 0);
    }
    #[test]
    fn commented_out_code_detects_semicolon_and_block_shapes() {
        let assignment = js_keys("// let total = compute(a, b);\n");
        assert_eq!(count_key(&assignment, "javascript:S125"), 1);

        let call = js_keys("// renderChart(data);\n");
        assert_eq!(count_key(&call, "javascript:S125"), 1);

        let block = js_keys("// { cleanup(); }\n");
        assert_eq!(count_key(&block, "javascript:S125"), 1);
    }

    #[test]
    fn commented_out_code_spares_tag_comments_even_if_code_like() {
        let tagged = js_keys("// FIXME: draw(x);\n");
        assert_eq!(count_key(&tagged, "javascript:S125"), 0);
    }
}
