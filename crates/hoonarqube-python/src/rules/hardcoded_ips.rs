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
        if let Some(address) = ip_addresses(&text).into_iter().next() {
            issues.push(Issue {
                rule_key: "python:S1313".to_string(),
                message: format!(
                    "Make sure using this hardcoded IP address \"{address}\" is safe here."
                ),
                range: to_range(range, index, source),
                fix: None,
                flows: Vec::new(),
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

#[cfg(test)]
mod compressed_ipv6_tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s1313_flags_compressed_ipv6_link_local() {
        let flagged = scan("H = \"fe80::1\"\n");
        assert!(!findings(&flagged, "python:S1313").is_empty());
    }

    #[test]
    fn s1313_time_stamps_still_clean_with_compression_fix() {
        // HH:MM:SS has 3 groups but no double colon → still clean.
        assert!(findings(&scan("T = \"12:34:56\"\n"), "python:S1313").is_empty());
    }
}
