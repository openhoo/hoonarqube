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
        let mut flagged = false;
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
                    flagged = true;
                }
                search = start;
            }
        }
        if flagged {
            issues.push(Issue {
                rule_key: "python:S5332".to_string(),
                message:
                    "Use an encrypted protocol such as HTTPS instead of this cleartext connection."
                        .to_string(),
                range: to_range(range, index, source),
                fix: None,
            });
        }
    }
    issues
}
