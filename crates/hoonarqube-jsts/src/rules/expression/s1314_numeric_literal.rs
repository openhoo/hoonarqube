// Rule module s1314_numeric_literal (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{NumericLiteral};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope};


/// `S1314` (legacy octal integer literals) and `S6534` (precision loss).
pub(crate) fn check_numeric_literal(sink: &mut IssueSink, it: &NumericLiteral<'_>) {
    let Some(raw) = &it.raw else {
        return;
    };
    let raw = raw.as_str();
    let digits = raw.trim_end_matches('n');
    if digits.len() > 1
        && digits.starts_with('0')
        && digits[1..].bytes().all(|byte| byte.is_ascii_digit())
    {
        sink.emit_span(
            RuleScope::Both,
            "S1314",
            "Use the \"0o\" prefix for octal literals.",
            it.span,
        );
    }
    if loses_precision(digits) {
        sink.emit_span(
            RuleScope::Both,
            "S6534",
            "This numeric literal exceeds safe precision; use BigInt or shorten it.",
            it.span,
        );
    }
}


pub(crate) fn loses_precision(digits: &str) -> bool {
    if digits.contains('.') || digits.contains('e') || digits.contains('E') {
        let significant = digits.chars().filter(char::is_ascii_digit).count();
        return significant > 17;
    }
    let cleaned = digits.trim_start_matches('0');
    i128::try_from(cleaned.len()).is_ok_and(|_| {
        cleaned
            .parse::<i128>()
            .is_ok_and(|value| value.abs() > 9_007_199_254_740_991)
    })
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S1314"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
