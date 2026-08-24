// Rule module s1314_numeric_literal (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::NumericLiteral;

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1314_flags_legacy_octal_integer_literal() {
        let findings = js_keys("let mode = 0755;\n");
        assert_eq!(count_key(&findings, "javascript:S1314"), 1);
    }

    #[test]
    fn s1314_allows_modern_and_plain_numerics() {
        let findings = js_keys("let octal = 0o755;\nlet plain = 755;\n");
        assert_eq!(count_key(&findings, "javascript:S1314"), 0);
    }

    #[test]
    fn s6534_flags_precision_loss_beyond_safe_integer_boundary() {
        let exact = js_keys("let ok = 9007199254740991;\n");
        assert_eq!(count_key(&exact, "javascript:S6534"), 0);

        let over = js_keys("let big = 9007199254740993;\n");
        assert_eq!(count_key(&over, "javascript:S6534"), 1);
    }
}
