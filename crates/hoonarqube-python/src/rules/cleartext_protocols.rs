use crate::support::collect_value_string_contents;
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
    // Sonar's CleartextProtocolFilter safe-host pattern: localhost,
    // loopback/link-local IPs, cloud metadata endpoints, and
    // example/test/localhost TLDs.
    const SAFE_HOSTS: [&str; 12] = [
        "localhost",
        "127.0.0.1",
        "::1",
        "169.254.0.0",
        "168.63.129.16",
        "100.100.100.200",
        "metadata.google.internal",
        "metadata.internal",
        "host.docker.internal",
        "gateway.docker.internal",
        "example.org",
        "example.com",
    ];
    // Sonar's CleartextProtocolFilter namespace-authority exemption list.
    const NAMESPACE_AUTHORITIES: [&str; 28] = [
        "www.w3.org",
        "schemas.android.com",
        "schemas.microsoft.com",
        "schemas.xmlsoap.org",
        "www.sap.com",
        "www.opengis.net",
        "hl7.org",
        "unitsofmeasure.org",
        "purl.org",
        "docs.oasis-open.org",
        "xmlns.com",
        "json-ld.org",
        "schema.org",
        "www.springframework.org",
        "www.mulesoft.org",
        "maven.apache.org",
        "dublincore.org",
        "ogp.me",
        "xml.apache.org",
        "schemas.openxmlformats.org",
        "rdfs.org",
        "schemas.google.com",
        "a9.com",
        "ns.adobe.com",
        "ltsc.ieee.org",
        "docbook.org",
        "graphml.graphdrawing.org",
        "json-schema.org",
    ];
    let mut issues = Vec::new();
    for (text, range) in collect_value_string_contents(parsed.syntax().body.as_slice()) {
        let mut flagged_protocol = None;
        for scheme in CLEARTEXT_SCHEMES {
            let mut search = 0usize;
            while let Some(relative) = text[search..].find(scheme) {
                let start = search + relative + scheme.len();
                // IPv6 literals are bracketed; the host ends at `]`.
                let host = if text[start..].starts_with('[') {
                    text[start..]
                        .find(']')
                        .map(|end| &text[start..=start + end])
                        .unwrap_or_default()
                } else {
                    text[start..]
                        .split(['/', ':', '?', '#'])
                        .next()
                        .unwrap_or_default()
                };
                let safe = SAFE_HOSTS.contains(&host)
                    || host.ends_with(".example.org")
                    || host.ends_with(".example.com")
                    || host.ends_with(".svc.cluster.local")
                    || host.rsplit_once('.').is_some_and(|(_, tld)| tld == "test")
                    || host.ends_with(".localhost")
                    || NAMESPACE_AUTHORITIES.contains(&host);
                // Sonar flags even a bare `http://` literal — the empty host
                // is not an exemption.
                if !safe {
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
                flows: Vec::new(),
                alternatives: Vec::new(),
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
        let bad = scan("web = 'http://unsafe.example/path'\nfiles = 'ftp://files.example/data'\n");
        assert_eq!(findings(&bad, "python:S5332").len(), 2);

        let good = scan("secure = 'https://unsafe.test'\nlocal = 'http://localhost:8000'\n");
        assert!(findings(&good, "python:S5332").is_empty());
    }
}

#[cfg(test)]
mod docstring_prose_tests {
    use crate::test_support::{findings, scan};

    // Issue #112: URLs in documentation strings are prose, not cleartext
    // communication; executable endpoint values keep reporting.

    #[test]
    fn s5332_module_docstring_documentation_url_is_clean() {
        let flagged =
            scan("\"\"\"Documentation: see http://yaml.org/ for the YAML specification.\"\"\"\n");
        assert!(findings(&flagged, "python:S5332").is_empty());
    }

    #[test]
    fn s5332_docstring_url_is_clean_but_endpoint_value_still_flags() {
        let source = concat!(
            "def fetch():\n",
            "    \"\"\"Reads the spec at http://yaml.org/spec.\"\"\"\n",
            "    return download(\"http://unsafe.example/data\")\n",
        );
        let flagged = scan(source);
        let found = findings(&flagged, "python:S5332");
        assert_eq!(found.len(), 1);
        assert!(
            found[0]
                .message
                .starts_with("Using http protocol is insecure")
        );
    }
}
