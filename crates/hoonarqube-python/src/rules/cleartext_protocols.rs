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
    let facts = WebFrameworkFacts::build(file_ctx);
    let patterns = protocol_identification_ranges(file_ctx, &facts);
    let mut issues = Vec::new();
    for_each_value_string_element(parsed.syntax().body.as_slice(), &mut |text, range| {
        if patterns.contains(&range) {
            return;
        }
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

/// Select the reference check's regular argument, then descend through tuples
/// only. Ruff already removes parentheses; calls and lists retain their own
/// context and must not inherit an outer protocol-identification exemption.
fn protocol_identification_ranges(
    file_ctx: &FileContext<'_>,
    facts: &WebFrameworkFacts<'_>,
) -> Vec<TextRange> {
    let mut ranges = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(method) = call.func.as_ref() else {
            continue;
        };
        if !matches!(
            method.attr.as_str(),
            "startswith" | "replace" | "removeprefix" | "removesuffix"
        ) || protocol_method_has_nonstring_owner(&method.value, method.attr.as_str(), facts)
        {
            continue;
        }
        let position = usize::from(is_builtin_protocol_type(&method.value, "str", facts));
        if let Some(argument) = call.arguments.args.get(position) {
            collect_protocol_pattern_ranges(argument, &mut ranges);
        }
    }
    ranges
}

fn collect_protocol_pattern_ranges(expr: &Expr, ranges: &mut Vec<TextRange>) {
    match expr {
        Expr::StringLiteral(literal) => {
            ranges.extend(literal.value.iter().map(Ranged::range));
        }
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_protocol_pattern_ranges(element, ranges);
            }
        }
        _ => {}
    }
}

fn is_builtin_protocol_type(expr: &Expr, expected: &str, facts: &WebFrameworkFacts<'_>) -> bool {
    let expr = facts.resolve_local_alias_chain(expr);
    match expr {
        Expr::Name(name)
            if name.id.as_str() == expected
                && matches!(
                    facts.resolve_name(expected, name.range()),
                    NameResolution::Unbound
                ) =>
        {
            true
        }
        Expr::Name(_) | Expr::Attribute(_) => facts
            .expr_fqn(expr)
            .is_some_and(|fqn| fqn == format!("builtins.{expected}")),
        _ => false,
    }
}

/// A missing or unresolved method has an unknown owner in `SonarPython` and
/// remains eligible. Only a proven non-string method owner rejects the pattern.
fn protocol_method_has_nonstring_owner(
    receiver: &Expr,
    method: &str,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    let receiver = facts.resolve_local_alias_chain(receiver);
    match receiver {
        Expr::BytesLiteral(_) => true,
        Expr::Call(call) => {
            protocol_type_has_nonstring_method(&call.func, method, facts, 0)
                || protocol_function_return_annotation(call, facts).is_some_and(|annotation| {
                    protocol_type_has_nonstring_method(annotation, method, facts, 0)
                })
                || protocol_expression_has_bytes_result(receiver, facts, 0)
        }
        Expr::Name(name) => {
            if let Some(parameter) = protocol_parameter(name, facts) {
                return parameter.annotation.as_deref().is_some_and(|annotation| {
                    protocol_type_has_nonstring_method(annotation, method, facts, 0)
                });
            }
            protocol_type_has_nonstring_method(receiver, method, facts, 0)
        }
        _ => protocol_type_has_nonstring_method(receiver, method, facts, 0),
    }
}

/// Declared results are proof only for a uniquely bound local bare function.
/// Parameters, imports, assignments and ambiguous writes keep the call unknown.
fn protocol_function_return_annotation<'a>(
    call: &ruff_python_ast::ExprCall,
    facts: &WebFrameworkFacts<'a>,
) -> Option<&'a Expr> {
    let Expr::Name(name) = call.func.as_ref() else {
        return None;
    };
    let function = facts.resolve_function(call)?;
    if protocol_name_has_definition(name, function.range(), facts) {
        function.returns.as_deref()
    } else {
        None
    }
}

fn protocol_name_has_definition(
    name: &ruff_python_ast::ExprName,
    definition: TextRange,
    facts: &WebFrameworkFacts<'_>,
) -> bool {
    for scope in facts.enclosing_chain(name.range()) {
        if let Some(range) = scope
            && protocol_scope_has_parameter(range, name.id.as_str(), facts) != Some(false)
        {
            return false;
        }
        let mut bindings = facts.stmts.iter().filter(|stmt| {
            protocol_statement_scope(stmt, facts) == scope
                && crate::support::stmt_store_names(stmt)
                    .iter()
                    .any(|binding| binding == name.id.as_str())
        });
        let Some(binding) = bindings.next() else {
            continue;
        };
        return bindings.next().is_none() && binding.range() == definition;
    }
    false
}

/// Inspect the actual function or lambda parameters before rejecting an outer
/// definition. An unrelated lambda parameter does not shadow that definition.
fn protocol_scope_has_parameter(
    scope: TextRange,
    name: &str,
    facts: &WebFrameworkFacts<'_>,
) -> Option<bool> {
    if let Some(function) = facts.functions.iter().find(|owner| owner.range() == scope) {
        return Some(protocol_function_parameter(function, name).is_some());
    }
    let mut result = None;
    for stmt in &facts.stmts {
        for_each_stmt_expr(std::slice::from_ref(*stmt), &mut |expr| {
            if let Expr::Lambda(lambda) = expr
                && lambda.range() == scope
            {
                result = Some(lambda.parameters.as_deref().is_some_and(|parameters| {
                    protocol_parameters_parameter(parameters, name).is_some()
                }));
            }
        });
        if result.is_some() {
            return result;
        }
    }
    None
}

fn protocol_statement_scope(stmt: &Stmt, facts: &WebFrameworkFacts<'_>) -> Option<TextRange> {
    facts
        .enclosing_chain(stmt.range())
        .into_iter()
        .find(|scope| *scope != Some(stmt.range()))
        .flatten()
}

/// Preserve the bytes result of the two transforms verified against the live
/// reference. Unknown calls and custom methods do not prove a bytes result.
fn protocol_expression_has_bytes_result(
    expr: &Expr,
    facts: &WebFrameworkFacts<'_>,
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    let is_bytes_type = |annotation: &Expr| {
        ["bytes", "bytearray"]
            .iter()
            .any(|name| is_builtin_protocol_type(annotation, name, facts))
    };
    match facts.resolve_local_alias_chain(expr) {
        Expr::BytesLiteral(_) => true,
        Expr::Name(name) => protocol_parameter(name, facts)
            .and_then(|parameter| parameter.annotation.as_deref())
            .is_some_and(is_bytes_type),
        Expr::Call(call) => {
            is_bytes_type(&call.func)
                || protocol_function_return_annotation(call, facts).is_some_and(is_bytes_type)
                || matches!(call.func.as_ref(), Expr::Attribute(method)
                    if matches!(method.attr.as_str(), "strip" | "lower")
                        && protocol_expression_has_bytes_result(&method.value, facts, depth + 1))
        }
        _ => false,
    }
}

fn protocol_type_has_nonstring_method(
    expr: &Expr,
    method: &str,
    facts: &WebFrameworkFacts<'_>,
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    let expr = facts.resolve_local_alias_chain(expr);
    if ["bytes", "bytearray"]
        .iter()
        .any(|name| is_builtin_protocol_type(expr, name, facts))
    {
        return true;
    }
    let Some(class) = protocol_class(expr, facts) else {
        return false;
    };
    if protocol_type_extends_string(expr, facts, depth) != Some(false) {
        return false;
    }
    class
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.as_str() == method))
        || class
            .bases()
            .iter()
            .any(|base| protocol_type_has_nonstring_method(base, method, facts, depth + 1))
}

fn protocol_type_extends_string(
    expr: &Expr,
    facts: &WebFrameworkFacts<'_>,
    depth: u32,
) -> Option<bool> {
    if depth > 8 {
        return None;
    }
    let expr = facts.resolve_local_alias_chain(expr);
    if is_builtin_protocol_type(expr, "str", facts) {
        return Some(true);
    }
    if [
        "object",
        "bytes",
        "bytearray",
        "int",
        "float",
        "bool",
        "list",
        "tuple",
        "dict",
        "set",
    ]
    .iter()
    .any(|name| is_builtin_protocol_type(expr, name, facts))
    {
        return Some(false);
    }
    let class = protocol_class(expr, facts)?;
    let mut unknown = false;
    for base in class.bases() {
        match protocol_type_extends_string(base, facts, depth + 1) {
            Some(true) => return Some(true),
            None => unknown = true,
            Some(false) => {}
        }
    }
    (!unknown).then_some(false)
}

fn protocol_class<'a>(
    expr: &Expr,
    facts: &WebFrameworkFacts<'a>,
) -> Option<&'a ruff_python_ast::StmtClassDef> {
    let expr = facts.resolve_local_alias_chain(expr);
    let class = facts.resolve_class_def(expr, expr.range())?;
    let proven = match expr {
        Expr::Name(name) => protocol_name_has_definition(name, class.range(), facts),
        Expr::Attribute(attribute) => protocol_class(&attribute.value, facts)
            .is_some_and(|owner| owner.body.iter().any(|stmt| stmt.range() == class.range())),
        _ => false,
    };
    proven.then_some(class)
}

fn protocol_parameter<'a>(
    name: &ruff_python_ast::ExprName,
    facts: &WebFrameworkFacts<'a>,
) -> Option<&'a ruff_python_ast::Parameter> {
    let scope = facts.enclosing_scope(name.range())?;
    let function = facts
        .functions
        .iter()
        .find(|function| function.range() == scope)?;
    protocol_function_parameter(function, name.id.as_str())
}

fn protocol_function_parameter<'a>(
    function: &'a ruff_python_ast::StmtFunctionDef,
    name: &str,
) -> Option<&'a ruff_python_ast::Parameter> {
    protocol_parameters_parameter(&function.parameters, name)
}

fn protocol_parameters_parameter<'a>(
    parameters: &'a ruff_python_ast::Parameters,
    name: &str,
) -> Option<&'a ruff_python_ast::Parameter> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|parameter| &parameter.parameter)
        .chain(parameters.vararg.as_deref())
        .chain(parameters.kwarg.as_deref())
        .find(|parameter| parameter.name.as_str() == name)
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

    #[test]
    fn s5332_protocol_identification_resolves_string_aliases_subclasses_and_unknown_methods() {
        let cases = [
            (
                "imported-type-alias",
                "from builtins import str as Text\nresult = Text.startswith(value, \"http://\")\n",
            ),
            (
                "imported-module-alias",
                "import builtins as b\nresult = b.str.startswith(value, \"http://\")\n",
            ),
            (
                "assigned-type-alias",
                "Text = str\nresult = Text.startswith(value, \"http://\")\n",
            ),
            (
                "string-subclass",
                "class Text(str):\n    pass\nresult = Text().startswith(\"http://\")\n",
            ),
            (
                "string-subclass-method",
                "class Text(str):\n    def startswith(self, value):\n        return value\nresult = Text().startswith(\"http://\")\n",
            ),
            (
                "unknown-local-method",
                "class Endpoint:\n    pass\nresult = Endpoint().startswith(\"http://\")\n",
            ),
            (
                "unknown-imported-method",
                "from other import Endpoint\nresult = Endpoint().startswith(\"http://\")\n",
            ),
            (
                "shadowed-class-name",
                "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify(Endpoint):\n    return Endpoint().startswith(\"http://\")\n",
            ),
        ];
        for (name, source) in cases {
            let report = scan(source);
            assert!(findings(&report, "python:S5332").is_empty(), "{name}");
        }
    }

    #[test]
    fn s5332_protocol_identification_keeps_known_nonstring_method_owners_unsafe() {
        let cases = [
            (
                "inherited-nonstr-method",
                "class Parent:\n    def startswith(self, value):\n        return value\nclass Child(Parent):\n    pass\nresult = Child().startswith(\"http://\")\n",
            ),
            (
                "typed-bytes-owner",
                "def identify(value: bytes):\n    return value.startswith(\"http://\")\n",
            ),
            (
                "typed-custom-owner",
                "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify(value: Endpoint):\n    return value.startswith(\"http://\")\n",
            ),
            (
                "imported-bytes-owner",
                "from builtins import bytes as Bytes\nresult = Bytes().startswith(\"http://\")\n",
            ),
            (
                "shadowed-builtin-class",
                "def identify(str):\n    return str.startswith(value, \"http://\")\n",
            ),
        ];
        for (name, source) in cases {
            let report = scan(source);
            let issues = findings(&report, "python:S5332");
            assert_eq!(issues.len(), 1, "{name}");
            assert_eq!(
                issues[0].message,
                "Using HTTP protocol is insecure. Use HTTPS instead."
            );
        }
    }
    #[test]
    fn s5332_protocol_identification_preserves_live_result_owner_boundaries() {
        // Exact sources and ranges from the supplemental live SonarQube scan.
        let cases = [
            (
                "bytes-strip.py",
                "result = b\"x\".strip().startswith(\"http://\")\n",
                Some((1, 33, 1, 42)),
            ),
            (
                "annotated-bytes.py",
                "def provide() -> bytes:\n    return b\"x\"\nresult = provide().startswith(\"http://\")\n",
                Some((3, 30, 3, 39)),
            ),
            (
                "bytes-lower.py",
                "def identify(value: bytes):\n    return value.lower().startswith(\"http://\")\n",
                Some((2, 36, 2, 45)),
            ),
            (
                "annotated-str.py",
                "def provide() -> str:\n    return \"x\"\nresult = provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "unknown-call.py",
                "from unknown import provide\nresult = provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "imported-str-alias.py",
                "from builtins import str as Text\nresult = Text.startswith(value, \"http://\")\n",
                None,
            ),
            (
                "annotated-custom.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\ndef provide() -> Endpoint:\n    return Endpoint()\nresult = provide().startswith(\"http://\")\n",
                Some((6, 30, 6, 39)),
            ),
            (
                "bytes-constructor.py",
                "result = bytes().startswith(\"http://\")\n",
                Some((1, 28, 1, 37)),
            ),
            ("bare.py", "endpoint = \"http://\"\n", Some((1, 11, 1, 20))),
        ];
        let mut mismatches = Vec::new();
        for (name, source, expected) in cases {
            let report = scan(source);
            let issues = findings(&report, "python:S5332");
            let actual: Vec<_> = issues
                .iter()
                .map(|issue| {
                    assert_eq!(
                        issue.message,
                        "Using HTTP protocol is insecure. Use HTTPS instead."
                    );
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    )
                })
                .collect();
            let expected: Vec<_> = expected.into_iter().collect();
            if actual != expected {
                mismatches.push((name, actual, expected));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }
    #[test]
    fn s5332_protocol_identification_preserves_live_shadowed_result_owners() {
        // Exact sources and ranges from the separate live binding-owner scan.
        let cases = [
            (
                "parameter-shadow.py",
                "def provide() -> bytes:\n    return b\"x\"\ndef identify(provide):\n    return provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "local-shadow.py",
                "def provide() -> bytes:\n    return b\"x\"\ndef identify():\n    provide = unknown\n    return provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "reassigned-provider.py",
                "def provide() -> bytes:\n    return b\"x\"\nprovide = unknown\nresult = provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "import-shadow.py",
                "def provide() -> bytes:\n    return b\"x\"\ndef identify():\n    from other import provide\n    return provide().startswith(\"http://\")\n",
                None,
            ),
            (
                "known-bytes.py",
                "def provide() -> bytes:\n    return b\"x\"\nresult = provide().startswith(\"http://\")\n",
                Some((3, 30, 3, 39)),
            ),
            (
                "bytes-decode.py",
                "result = b\"x\".decode().startswith(\"http://\")\n",
                None,
            ),
            (
                "unknown-bytes-method.py",
                "result = b\"x\".unknown().startswith(\"http://\")\n",
                None,
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, source, expected) in cases {
            let report = scan(source);
            let issues = findings(&report, "python:S5332");
            let actual: Vec<_> = issues
                .iter()
                .map(|issue| {
                    assert_eq!(
                        issue.message,
                        "Using HTTP protocol is insecure. Use HTTPS instead."
                    );
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    )
                })
                .collect();
            let expected: Vec<_> = expected.into_iter().collect();
            if actual != expected {
                mismatches.push((name, actual, expected));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }
    #[test]
    fn s5332_protocol_identification_preserves_live_shadowed_class_owners() {
        // Exact sources and ranges from the separate live class-owner scan.
        let cases = [
            (
                "class-import-shadow.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nfrom other import Endpoint\nresult = Endpoint().startswith(\"http://\")\n",
                None,
            ),
            (
                "class-local-import-shadow.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify():\n    from other import Endpoint\n    return Endpoint().startswith(\"http://\")\n",
                None,
            ),
            (
                "class-reassignment.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nEndpoint = unknown\nresult = Endpoint().startswith(\"http://\")\n",
                None,
            ),
            (
                "class-parameter-shadow.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify(Endpoint):\n    return Endpoint().startswith(\"http://\")\n",
                None,
            ),
            (
                "class-lambda-shadow.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
                None,
            ),
            (
                "nested-class-parameter.py",
                "class Container:\n    class Endpoint:\n        def startswith(self, value):\n            return value\ndef identify(Container):\n    return Container.Endpoint().startswith(\"http://\")\n",
                None,
            ),
            (
                "known-class.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = Endpoint().startswith(\"http://\")\n",
                Some((4, 31, 4, 40)),
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, source, expected) in cases {
            let report = scan(source);
            let issues = findings(&report, "python:S5332");
            let actual: Vec<_> = issues
                .iter()
                .map(|issue| {
                    assert_eq!(
                        issue.message,
                        "Using HTTP protocol is insecure. Use HTTPS instead."
                    );
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    )
                })
                .collect();
            let expected: Vec<_> = expected.into_iter().collect();
            if actual != expected {
                mismatches.push((name, actual, expected));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }
    #[test]
    fn s5332_protocol_identification_preserves_live_lambda_owner_boundaries() {
        // Exact sources and ranges from the separate live lambda-owner scan.
        let cases = [
            (
                "class-lambda-unshadowed.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda : Endpoint().startswith(\"http://\"))()\n",
                Some((4, 41, 4, 50)),
            ),
            (
                "class-lambda-unrelated.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda other: Endpoint().startswith(\"http://\"))(unknown)\n",
                Some((4, 46, 4, 55)),
            ),
            (
                "class-lambda-shadowed.py",
                "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
                None,
            ),
            (
                "function-lambda-unshadowed.py",
                "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda : Endpoint().startswith(\"http://\"))()\n",
                Some((3, 41, 3, 50)),
            ),
            (
                "function-lambda-unrelated.py",
                "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda other: Endpoint().startswith(\"http://\"))(unknown)\n",
                Some((3, 46, 3, 55)),
            ),
            (
                "function-lambda-shadowed.py",
                "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
                None,
            ),
        ];
        let mut mismatches = Vec::new();
        for (name, source, expected) in cases {
            let report = scan(source);
            let issues = findings(&report, "python:S5332");
            let actual: Vec<_> = issues
                .iter()
                .map(|issue| {
                    assert_eq!(
                        issue.message,
                        "Using HTTP protocol is insecure. Use HTTPS instead."
                    );
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    )
                })
                .collect();
            let expected: Vec<_> = expected.into_iter().collect();
            if actual != expected {
                mismatches.push((name, actual, expected));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }
}
