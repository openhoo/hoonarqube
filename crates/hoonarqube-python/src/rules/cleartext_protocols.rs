use crate::support::{for_each_stmt, for_each_stmt_expr, to_range};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

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
    for_each_value_string_element(parsed.syntax().body.as_slice(), &mut |text, range| {
        let mut flagged_protocol = None;
        for scheme in CLEARTEXT_SCHEMES {
            // Only endpoint values, not a URI embedded in prose or another URL.
            if let Some(authority) = text.strip_prefix(scheme) {
                let host = protocol_host(authority);
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
    });
    issues
}

fn for_each_value_string_element(stmts: &[Stmt], visit: &mut impl FnMut(&str, TextRange)) {
    let mut docstrings = Vec::new();
    let mut collect_docstring = |suite: &[Stmt]| {
        if let Some(first) = suite.first()
            && ruff_python_ast::helpers::is_docstring_stmt(first)
            && let Stmt::Expr(statement) = first
        {
            docstrings.push(statement.value.range());
        }
    };
    collect_docstring(stmts);
    for_each_stmt(stmts, &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => collect_docstring(&function.body),
        Stmt::ClassDef(class) => collect_docstring(&class.body),
        _ => {}
    });
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::StringLiteral(literal) = expr
            && !docstrings.contains(&literal.range())
        {
            // S5332 checks each token, including a URL after concatenated prose.
            // Other rules keep consuming the shared collector's combined value.
            for part in &literal.value {
                visit(&part.value, part.range());
            }
        }
    });
}

fn protocol_host(authority: &str) -> &str {
    // IPv6 literals are bracketed; compare the address without its delimiters.
    if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| &authority[1..end])
            .unwrap_or_default()
    } else {
        authority
            .split(['/', ':', '?', '#'])
            .next()
            .unwrap_or_default()
    }
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

    #[test]
    fn s5332_checks_concatenated_tokens_without_reporting_docstrings() {
        let report = scan(concat!(
            "('module ' 'http://remote.invalid/doc')\n",
            "class Feed:\n",
            "    ('class ' 'http://remote.invalid/doc')\n",
            "    def render(self):\n",
            "        ('function ' 'http://remote.invalid/doc')\n",
            "        return ('See ' \n",
            "                'http://remote.invalid/profile')\n",
            "embedded = 'See http://remote.invalid/profile'\n",
            "namespace = ('See ' 'http://www.w3.org/2005/Atom')\n",
            "split_scheme = ('http' '://remote.invalid')\n",
        ));
        let found = findings(&report, "python:S5332");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 7);
        assert_eq!(found[0].range.start.column, 16);
        assert_eq!(found[0].range.end.line, 7);
        assert_eq!(found[0].range.end.column, 47);
    }

    #[test]
    fn s5332_requires_a_value_prefix_and_preserves_bare_schemes() {
        let source = concat!(
            "a = \"http://\"\n",
            "b = value.startswith((\"http://\", \"https://\", \"/\"))\n",
            "c = \"see http://www.rssboard.org/rss-profile for details\"\n",
            "ns = \"http://www.w3.org/2005/Atom\"\n",
            "ns2 = \"http://purl.org/dc/elements/1.1/\"\n",
            "space = \" http://remote.invalid\"\n",
            "secure = \"https://remote.invalid/?next=http://remote.invalid\"\n",
            "local = \"http://localhost/?next=ftp://remote.invalid\"\n",
            "endpoint = \"http://remote.invalid/?next=ftp://remote.invalid\"\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S5332");
        assert_eq!(
            found
                .iter()
                .map(|issue| (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column
                ))
                .collect::<Vec<_>>(),
            vec![(1, 4, 1, 13), (2, 22, 2, 31), (9, 11, 9, 61)]
        );
        assert!(
            found
                .iter()
                .all(|issue| issue.message.starts_with("Using http"))
        );
    }

    #[test]
    fn s5332_exempts_bracketed_loopback_but_not_remote_ipv6() {
        // CleartextProtocolFilter's safe-host pattern accepts optional IPv6 brackets.
        let report = scan(concat!(
            "local = 'http://[::1]:8000/path'\n",
            "remote = 'http://[2001:db8::1]:8000/path'\n",
        ));
        let found = findings(&report, "python:S5332");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
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
