use crate::engine::file_context::FileContext;
use crate::support::{
    NameResolution, WebFrameworkFacts, for_each_stmt, for_each_stmt_expr, issue_at, to_range,
};
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
    file_ctx: &FileContext<'_>,
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
                    "http" => "Using HTTP protocol is insecure. Use HTTPS instead.",
                    "ftp" => "Using FTP protocol is insecure. Use SFTP, SCP or FTPS instead.",
                    "telnet" => "Using Telnet protocol is insecure. Use SSH instead.",
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
    if !file_ctx.calls.iter().any(|call| matches!(call.func.as_ref(), Expr::Attribute(method) if matches!(method.attr.as_str(), "serve_forever" | "server_bind"))) {
        return issues;
    }
    let facts = WebFrameworkFacts::build(file_ctx);
    for call in &file_ctx.calls {
        if sensitive_http_super_call(call, &facts) {
            issues.push(issue_at(
                "python:S5332",
                "Using HTTP protocol is insecure. Use HTTPS instead.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// The super-call contract depends on the enclosing class's imported base,
/// not the class name or the last segment of the method. Unknown bases and
/// locally replaced `super` bindings do not prove an HTTP server operation.
fn sensitive_http_super_call(
    call: &ruff_python_ast::ExprCall,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    let Expr::Attribute(method) = call.func.as_ref() else {
        return false;
    };
    if !matches!(method.attr.as_str(), "serve_forever" | "server_bind") {
        return false;
    }
    let Expr::Call(receiver) = method.value.as_ref() else {
        return false;
    };
    let Expr::Name(super_name) = receiver.func.as_ref() else {
        return false;
    };
    if super_name.id.as_str() != "super"
        || !matches!(
            facts.resolve_name("super", receiver.range()),
            NameResolution::Unbound
        )
    {
        return false;
    }
    facts.enclosing_class(call.range()).is_some_and(|class| {
        class.bases().iter().any(|base| {
            facts.expr_fqn(base).is_some_and(|fqn| {
                matches!(
                    fqn.as_str(),
                    "http.server.HTTPServer" | "http.server.ThreadingHTTPServer"
                )
            })
        })
    })
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
    fn s5332_resolves_http_server_super_calls_through_import_aliases() {
        let source = concat!(
            "from http.server import HTTPServer as Server\n",
            "class Development(Server):\n",
            "    def serve_forever(self, poll_interval=0.5):\n",
            "        super().serve_forever(poll_interval=poll_interval)\n",
        );
        let report = scan(source);
        let issues = findings(&report, "python:S5332");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Using HTTP protocol is insecure. Use HTTPS instead."
        );
        assert_eq!(issues[0].range.start.line, 4);
        assert_eq!(issues[0].range.start.column, 8);
        assert_eq!(issues[0].range.end.column, 58);
    }

    #[test]
    fn s5332_requires_http_base_provenance_and_an_unshadowed_super() {
        let source = concat!(
            "from http.server import HTTPServer\n",
            "class Other(Unknown):\n",
            "    def serve(self):\n        super().serve_forever()\n",
            "class Shadowed(HTTPServer):\n",
            "    def serve(self, super):\n        super().serve_forever()\n",
            "HTTPServer = factory()\n",
            "class Rebound(HTTPServer):\n",
            "    def serve(self):\n        super().server_bind()\n",
        );
        assert!(findings(&scan(source), "python:S5332").is_empty());
    }

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
            vec![(1, 4, 1, 13), (9, 11, 9, 61)]
        );
        assert!(
            found
                .iter()
                .all(|issue| issue.message.starts_with("Using HTTP"))
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
                .starts_with("Using HTTP protocol is insecure")
        );
    }
}

#[cfg(test)]
mod protocol_identification_tests {
    use crate::test_support::{findings, scan};

    // Current installed SonarPython protocol-identification semantics; bare
    // endpoint values remain unsafe under the original #642 / #705 contract.

    #[test]
    fn s5332_protocol_identification_patterns_are_not_endpoint_values() {
        {
            let source =
                "def launch(url: str):\n    return url.startswith((\"http://\", \"https://\"))\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "original-click-reduction");
        }
        {
            let source = "result = \"https://safe.invalid\".startswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "literal-instance-startswith");
        }
        {
            let source = "def identify(value: str):\n    return value.startswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "typed-instance-startswith");
        }
        {
            let source =
                "def identify(value: str):\n    return value.startswith((((\"http://\",),)))\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "nested-tuple-parentheses");
        }
        {
            let source =
                "def identify(value: str):\n    return value.replace(\"http://\", \"https://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "replace-old-pattern");
        }
        {
            let source = "def identify(value: str):\n    return value.removeprefix(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "remove-prefix-pattern");
        }
        {
            let source = "def identify(value: str):\n    return value.removesuffix(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "remove-suffix-pattern");
        }
        {
            let source = "result = str.startswith(value, \"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "unbound-str-pattern");
        }
        {
            let source = "def identify(value: str):\n    return value.startswith(\"http://remote.invalid/path\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "full-endpoint-pattern");
        }
        {
            let source = "def identify(value):\n    return value.startswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "unknown-receiver-method");
        }
        {
            let source = "a = \"http://\"\nb = value.startswith((\"http://\", \"https://\", \"/\"))\nc = \"see http://www.rssboard.org/rss-profile for details\"\nns = \"http://www.w3.org/2005/Atom\"\nns2 = \"http://purl.org/dc/elements/1.1/\"\nspace = \" http://remote.invalid\"\nsecure = \"https://remote.invalid/?next=http://remote.invalid\"\nlocal = \"http://localhost/?next=ftp://remote.invalid\"\nendpoint = \"http://remote.invalid/?next=ftp://remote.invalid\"\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 2, "prior-committed-bare-contract");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (1, 4, 1, 13)
            );
            assert_eq!(
                (
                    found[1].range.start.line,
                    found[1].range.start.column,
                    found[1].range.end.line,
                    found[1].range.end.column
                ),
                (9, 11, 9, 61)
            );
        }
    }

    #[test]
    fn s5332_protocol_identification_preserves_argument_and_owner_boundaries() {
        {
            let source = "value = \"http://\"\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "bare-assignment-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (1, 8, 1, 17)
            );
        }
        {
            let source = "def configure(self):\n    self.mount(\"http://\", object())\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "requests-mount-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 15, 2, 24)
            );
        }
        {
            let source = "def identify(value: str):\n    return value.startswith(\"https://\", \"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "startswith-later-position");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 40, 2, 49)
            );
        }
        {
            let source =
                "def identify(value: str):\n    return value.startswith(prefix=\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "startswith-keyword-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 35, 2, 44)
            );
        }
        {
            let source =
                "def identify(value: str):\n    return value.replace(\"https://\", \"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "replace-new-endpoint");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 37, 2, 46)
            );
        }
        {
            let source = "def identify(value: str):\n    return value.endswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "endswith-name-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 26, 2, 35)
            );
        }
    }

    #[test]
    fn s5332_protocol_identification_preserves_owner_and_wrapper_boundaries() {
        {
            let source = "result = str.startswith(\"http://\", \"https://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "unbound-str-receiver-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (1, 24, 1, 33)
            );
        }
        {
            let source = "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = Endpoint().startswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "known-nonstr-owner-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (4, 31, 4, 40)
            );
        }
        {
            let source = "def identify(value: str):\n    return value.startswith([\"http://\"])\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "list-wrapper-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 29, 2, 38)
            );
        }
        {
            let source =
                "def identify(value: str):\n    return value.startswith(make(\"http://\"))\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "nested-call-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 33, 2, 42)
            );
        }
        {
            let source =
                "value = b\"https://safe.invalid\"\nresult = value.startswith(\"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "known-bytes-owner-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (2, 26, 2, 35)
            );
        }
        {
            let source = "class str:\n    @staticmethod\n    def startswith(receiver, prefix):\n        return prefix\nresult = str.startswith(None, \"http://\")\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 1, "rebound-str-class-guard");
            assert_eq!(
                (
                    found[0].range.start.line,
                    found[0].range.start.column,
                    found[0].range.end.line,
                    found[0].range.end.column
                ),
                (5, 30, 5, 39)
            );
        }
    }

    #[test]
    fn s5332_protocol_identification_keeps_existing_clean_controls() {
        {
            let source = "secure = \"https://remote.invalid\"\nlocal = \"http://localhost:8000\"\nprose = \"See http://remote.invalid\"\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "clean-secure-safe-prose");
        }
        {
            let source =
                "def describe():\n    \"\"\"http://remote.invalid\"\"\"\n    return None\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "docstring-clean");
        }
    }

    #[test]
    fn s5332_protocol_identification_unicode_crlf_retains_endpoint_coordinates() {
        {
            let source = "marker = \"😀\"; result = \"url\".startswith(\"http://\")\r\n";
            let report = scan(source);
            let found = findings(&report, "python:S5332");
            assert_eq!(found.len(), 0, "unicode-crlf-pattern");
        }
    }
}
