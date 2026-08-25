// Rule module s1313_string_literal_raw (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::StringLiteral;

/// Raw-text rules on string literals: `S1516` (multi-line), `S3786`
/// (`${…}` inside a regular string), and `S6535` (unnecessary escapes).
pub(crate) fn check_string_literal_raw(sink: &mut IssueSink, it: &StringLiteral<'_>) {
    // `S1313`: dotted-quad IPv4 literals.
    if is_ipv4_like(it.value.as_str()) {
        sink.emit_span(
            RuleScope::Both,
            "S1313",
            "Remove this hard-coded IP address.",
            it.span,
        );
    }
    let Some(raw) = &it.raw else {
        return;
    };
    if raw.contains('\n') {
        sink.emit_span(
            RuleScope::Both,
            "S1516",
            "Use a template literal for multi-line strings.",
            it.span,
        );
    }
    if raw.contains("${") {
        sink.emit_span(
            RuleScope::Both,
            "S3786",
            "Use a template literal if \"${}\" interpolation was intended.",
            it.span,
        );
    }
    if has_unnecessary_escape(raw) {
        sink.emit_span(
            RuleScope::Both,
            "S6535",
            "Remove the unnecessary escape sequence from this string.",
            it.span,
        );
    }
}

/// Whether `text` is exactly a dotted-quad IPv4 address (no octal-style
/// leading zeros, each octet at most 255).
fn is_ipv4_like(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
                && part.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// A backslash followed by a character that does not need escaping.
fn has_unnecessary_escape(raw: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    let meaningful = [
        b'n', b't', b'r', b'b', b'f', b'v', b'x', b'u', b'\\', b'\'', b'"', b'`', b'0',
    ];
    chars.windows(2).any(|window| {
        window[0] == '\\'
            && window[1].is_ascii_alphanumeric()
            && !meaningful.contains(&(window[1] as u8))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1313_flags_hardcoded_ipv4_literals() {
        let findings = js_keys("let a = \"192.168.0.1\";\nlet b = '10.0.0.1';\n");
        assert_eq!(count_key(&findings, "javascript:S1313"), 2);
    }

    #[test]
    fn s1313_allows_hostnames_and_invalid_octets() {
        let findings = js_keys(
            "let h = \"example.com\";\nlet big = \"300.1.1.1\";\nlet lead = \"01.2.3.4\";\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1313"), 0);
    }

    #[test]
    fn s3786_and_s6535_flag_interpolation_lookalike_and_needless_escape() {
        let findings = js_keys("let s = \"${x}\\a\";\n");
        assert_eq!(count_key(&findings, "javascript:S3786"), 1);
        assert_eq!(count_key(&findings, "javascript:S6535"), 1);
    }
}
