// Rule module s1313_string_literal_raw (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::StringLiteral;

/// Raw-text rules on string literals: `S1516` (multi-line), `S3786`
/// (`${…}` inside a regular string), and `S6535` (unnecessary escapes).
pub(crate) fn check_string_literal_raw(sink: &mut IssueSink, it: &StringLiteral<'_>) {
    // `S1313`: hard-coded IPv4/IPv6 address literals.
    if is_hardcoded_ip(it.value.as_str()) {
        sink.emit_span(
            RuleScope::Both,
            "S1313",
            &format!(
                "Make sure using a hardcoded IP address {} is safe here.",
                it.value
            ),
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
            "Multiline support is limited to browsers supporting ES5 only.",
            it.span,
        );
    }
    if raw.contains("${") {
        sink.emit_span(
            RuleScope::Both,
            "S3786",
            "Unexpected template string expression.",
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

/// Whether `text` is a hard-coded IP address: a dotted-quad IPv4 address
/// or an IPv6 address in full or compressed form. Loopback, wildcard, and
/// broadcast IPv4 addresses plus the bare `::` / `::1` localhost forms are
/// exempt per the RSPEC, mirroring the Python family.
fn is_hardcoded_ip(text: &str) -> bool {
    is_ipv4_address(text) || is_ipv6_address(text)
}

/// Whether `text` is exactly a dotted-quad IPv4 address (no octal-style
/// leading zeros, each octet at most 255).
fn is_ipv4_address(text: &str) -> bool {
    const EXEMPT: [&str; 3] = ["0.0.0.0", "127.0.0.1", "255.255.255.255"];
    if EXEMPT.contains(&text) {
        return false;
    }
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

/// Loose IPv6 grammar shared with the Python family (deliberately not a
/// strict RFC parser): eight hexdigit groups, or a `::` compression with at
/// least one visible group of at most four hexdigit characters.
fn is_ipv6_address(text: &str) -> bool {
    if text == "::" || text == "::1" {
        return false;
    }
    let groups: Vec<&str> = text.split(':').filter(|group| !group.is_empty()).collect();
    let has_double_colon = text.contains("::");
    (groups.len() == 8 || (has_double_colon && !groups.is_empty()))
        && groups
            .iter()
            .all(|group| group.len() <= 4 && group.bytes().all(|byte| byte.is_ascii_hexdigit()))
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
    fn s1313_spares_local_and_wildcard_addresses_like_the_python_family() {
        let findings = js_keys(
            "let a = \"127.0.0.1\";\nlet b = \"0.0.0.0\";\nlet c = \"255.255.255.255\";\nlet d = \"::\";\nlet e = \"::1\";\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1313"), 0);
    }

    #[test]
    fn s1313_flags_ipv6_literals_like_the_python_family() {
        let findings = js_keys("let a = \"2001:db8::1\";\nlet b = \"fe80::1\";\n");
        assert_eq!(count_key(&findings, "javascript:S1313"), 2);
    }

    #[test]
    fn s3786_and_s6535_flag_interpolation_lookalike_and_needless_escape() {
        let findings = js_keys("let s = \"${x}\\a\";\n");
        assert_eq!(count_key(&findings, "javascript:S3786"), 1);
        assert_eq!(count_key(&findings, "javascript:S6535"), 1);
    }
}
