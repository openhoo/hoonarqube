use crate::support::collect_string_contents;
use crate::support::ip_addresses;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// ---------------------------------------------------------------------------
// python:S1313 — hardcoded IP addresses in string literals.
// ---------------------------------------------------------------------------

pub(crate) fn check_hardcoded_ips(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if !ip_addresses(&text).is_empty() {
            issues.push(Issue {
                rule_key: "python:S1313".to_string(),
                message: "Make this IP address configurable.".to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s1313_flags_ipv4_and_ipv6() {
        let flagged = scan("ip = \"192.168.1.1\"\nhost = \"2001:db8::1\"\n");
        assert!(!findings(&flagged, "python:S1313").is_empty());
    }

    #[test]
    fn s1313_time_strings_are_clean() {
        let flagged = scan("t = \"10:00\"\n");
        assert!(findings(&flagged, "python:S1313").is_empty());
    }

    #[test]
    fn s1313_localhost_is_exempt() {
        let flagged = scan("ip = \"127.0.0.1\"\n");
        assert!(findings(&flagged, "python:S1313").is_empty());
    }
}
