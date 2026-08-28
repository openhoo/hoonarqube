use crate::support::collect_string_contents;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// ---------------------------------------------------------------------------
// python:S5332 — cleartext protocols in string literals.
// ---------------------------------------------------------------------------

pub(crate) fn check_cleartext_protocols(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const CLEARTEXT_SCHEMES: [&str; 3] = ["http://", "ftp://", "telnet://"];
    const SAFE_HOSTS: [&str; 5] = [
        "localhost",
        "127.0.0.1",
        "::1",
        "example.org",
        "example.com",
    ];
    let mut issues = Vec::new();
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        let mut flagged_protocol = None;
        for scheme in CLEARTEXT_SCHEMES {
            let mut search = 0usize;
            while let Some(relative) = text[search..].find(scheme) {
                let start = search + relative + scheme.len();
                let host = text[start..]
                    .split(['/', ':', '?', '#'])
                    .next()
                    .unwrap_or_default();
                let safe = SAFE_HOSTS.contains(&host)
                    || host.ends_with(".example.org")
                    || host.ends_with(".example.com");
                if !safe && !host.is_empty() {
                    flagged_protocol = Some(scheme.trim_end_matches("://"));
                }
                search = start;
            }
        }
        if let Some(protocol) = flagged_protocol {
            issues.push(Issue {
                rule_key: "python:S5332".to_string(),
                message: match protocol {
                    "http" => "Using http protocol is insecure. Use https instead",
                    "ftp" => "Using ftp protocol is insecure. Use sftp, scp or ftps instead",
                    "telnet" => "Using telnet protocol is insecure. Use ssh instead",
                    _ => unreachable!("fixed cleartext protocol list"),
                }
                .to_string(),
                range: to_range(range, index, source),
                fix: None,
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5332_flags_remote_cleartext_urls_and_spares_safe_hosts() {
        let bad = scan("web = 'http://unsafe.test/path'\nfiles = 'ftp://files.test/data'\n");
        assert_eq!(findings(&bad, "python:S5332").len(), 2);

        let good = scan("secure = 'https://unsafe.test'\nlocal = 'http://localhost:8000'\n");
        assert!(findings(&good, "python:S5332").is_empty());
    }
}
