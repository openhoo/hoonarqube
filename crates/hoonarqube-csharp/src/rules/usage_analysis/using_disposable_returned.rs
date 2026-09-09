use super::support::collect_in_callable;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, base_simple_names, canonical_identifier, collect_kinds, containing_namespace,
    is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, first_named_child, invocation_receiver, resolved_identifier_type,
};
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

fn normalized_type_name(text: &str) -> String {
    let mut text = text.trim().replace(' ', "");
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim_end_matches('?').to_string()
}

fn using_directive_text<'a>(using: Node<'_>, source: &'a str) -> &'a str {
    node_text(using, source)
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_start_matches("global")
        .trim()
        .trim_start_matches("using")
        .trim()
}

fn using_applies(using: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let using_namespace = containing_namespace(using, source);
    using_namespace.is_empty() || using_namespace == containing_namespace(use_site, source)
}

fn using_alias_target(
    root: Node<'_>,
    use_site: Node<'_>,
    alias: &str,
    target: &str,
    source: &str,
) -> bool {
    let target = normalized_type_name(target);
    let target = target.strip_prefix("global::").unwrap_or(&target);
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| {
            let text = using_directive_text(using, source);
            let Some((left, right)) = text.split_once('=') else {
                return false;
            };
            let actual = normalized_type_name(right);
            let actual = actual.strip_prefix("global::").unwrap_or(&actual);
            canonical_identifier(left.trim()) == canonical_identifier(alias) && actual == target
        })
}

fn has_namespace_import(root: Node<'_>, use_site: Node<'_>, namespace: &str, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| using_directive_text(using, source) == namespace)
        || containing_namespace(use_site, source) == namespace
}

fn source_declares_simple_type(root: Node<'_>, wanted: &str, source: &str) -> bool {
    collect_kinds(
        root,
        &[
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    )
    .into_iter()
    .filter_map(|declaration| declaration.child_by_field_name("name"))
    .any(|name| canonical_identifier(node_text(name, source)) == wanted)
}

fn is_local_disposable_type(
    root: Node<'_>,
    use_site: Node<'_>,
    type_node: Node<'_>,
    source: &str,
) -> bool {
    let wanted = simple_name(node_text(type_node, source));
    collect_kinds(
        root,
        &[
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    )
    .into_iter()
    .filter(|declaration| {
        declaration
            .child_by_field_name("name")
            .is_some_and(|name| simple_name(node_text(name, source)) == wanted)
    })
    .any(|declaration| {
        base_simple_names(declaration, source)
            .into_iter()
            .any(|base| {
                base == "IDisposable"
                    && (has_namespace_import(root, use_site, "System", source)
                        || using_alias_target(
                            root,
                            use_site,
                            "IDisposable",
                            "System.IDisposable",
                            source,
                        )
                        || node_text(declaration, source).contains("System.IDisposable"))
            })
    })
}

const IO_DISPOSABLE_TYPES: [&str; 13] = [
    "Stream",
    "FileStream",
    "MemoryStream",
    "StreamReader",
    "StreamWriter",
    "BinaryReader",
    "BinaryWriter",
    "TextReader",
    "TextWriter",
    "StringReader",
    "StringWriter",
    "BufferedStream",
    "NetworkStream",
];

fn is_known_disposable_type(
    root: Node<'_>,
    use_site: Node<'_>,
    type_node: Node<'_>,
    source: &str,
) -> bool {
    let raw = normalized_type_name(node_text(type_node, source));
    let bare = raw.strip_prefix("global::").unwrap_or(&raw);
    if bare == "System.IDisposable" {
        return true;
    }
    if bare == "IDisposable" {
        return has_namespace_import(root, use_site, "System", source)
            && !source_declares_simple_type(root, "IDisposable", source);
    }
    let simple = simple_name(&raw);
    if IO_DISPOSABLE_TYPES.contains(&simple) {
        if bare.starts_with("System.IO.") {
            return true;
        }
        if using_alias_target(
            root,
            use_site,
            simple,
            &format!("System.IO.{simple}"),
            source,
        ) {
            return true;
        }
        return has_namespace_import(root, use_site, "System.IO", source)
            && !source_declares_simple_type(root, simple, source);
    }
    if IO_DISPOSABLE_TYPES.iter().any(|known| {
        using_alias_target(
            root,
            use_site,
            simple,
            &format!("System.IO.{known}"),
            source,
        )
    }) {
        return true;
    }
    false
}

fn factory_returns_disposable(
    root: Node<'_>,
    use_site: Node<'_>,
    initializer: Node<'_>,
    source: &str,
) -> bool {
    if initializer.kind() != "invocation_expression" {
        return false;
    }
    let Some(method) = callee_name(initializer, source) else {
        return false;
    };
    if !matches!(method, "OpenRead" | "OpenWrite" | "Open" | "Create") {
        return false;
    }
    let Some(receiver) = invocation_receiver(initializer) else {
        return false;
    };
    let receiver_name = normalized_type_name(node_text(receiver, source));
    let receiver_name = receiver_name
        .strip_prefix("global::")
        .unwrap_or(&receiver_name);
    if receiver_name == "System.IO.File"
        || (receiver_name == "File"
            && has_namespace_import(root, use_site, "System.IO", source)
            && !source_declares_simple_type(root, "File", source))
        || (receiver.kind() == "identifier"
            && using_alias_target(
                root,
                use_site,
                canonical_identifier(node_text(receiver, source)),
                "System.IO.File",
                source,
            ))
    {
        return true;
    }
    receiver.kind() == "identifier"
        && resolved_identifier_type(receiver, source)
            .is_some_and(|type_name| simple_name(type_name) == "FileInfo")
}

fn resource_is_disposable(
    root: Node<'_>,
    use_site: Node<'_>,
    declaration: Node<'_>,
    initializer: Node<'_>,
    source: &str,
) -> bool {
    declaration
        .child_by_field_name("type")
        .is_some_and(|type_node| {
            is_known_disposable_type(root, use_site, type_node, source)
                || is_local_disposable_type(root, use_site, type_node, source)
        })
        || initializer.kind() == "object_creation_expression"
        || initializer
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                is_known_disposable_type(root, use_site, type_node, source)
                    || is_local_disposable_type(root, use_site, type_node, source)
            })
        || initializer.kind() == "object_creation_expression"
            && initializer
                .child_by_field_name("type")
                .or_else(|| first_named_child(initializer))
                .is_some_and(|type_node| {
                    is_known_disposable_type(root, initializer, type_node, source)
                        || is_local_disposable_type(root, initializer, type_node, source)
                })
        || factory_returns_disposable(root, use_site, initializer, source)
}

fn returned_identifier(return_statement: Node<'_>) -> Option<Node<'_>> {
    let mut expression = first_named_child(return_statement)?;
    while expression.kind() == "parenthesized_expression" {
        expression = first_named_child(expression)?;
    }
    (expression.kind() == "identifier").then_some(expression)
}

fn body_returns_resource(
    body: Node<'_>,
    using_node: Node<'_>,
    name: Node<'_>,
    source: &str,
) -> bool {
    let wanted = canonical_identifier(node_text(name, source));
    collect_in_callable(body, "return_statement")
        .into_iter()
        .filter(|return_statement| return_statement.start_byte() > using_node.start_byte())
        .filter_map(returned_identifier)
        .any(|expression| canonical_identifier(node_text(expression, source)) == wanted)
}

fn report_using(language: CsLanguage, using_node: Node<'_>, name: Node<'_>, source: &str) -> Issue {
    let keyword = collect_kinds(using_node, &["using"])
        .into_iter()
        .next()
        .unwrap_or(using_node);
    issue(
        language,
        "S2997",
        format!(
            "Remove the 'using' statement; it will cause automatic disposal of '{}'.",
            node_text(name, source)
        ),
        range_of(keyword, source),
    )
}

/// csharpsquid:S2997 — disposables returned from inside their own `using`.
fn is_using_local_declaration(node: Node<'_>) -> bool {
    if node.kind() != "local_declaration_statement" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "using")
}

pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut using_nodes = collect_kinds(root, &["using_statement"]);
    using_nodes.extend(
        collect_kinds(root, &["local_declaration_statement"])
            .into_iter()
            .filter(|node| is_using_local_declaration(*node)),
    );
    let mut issues = Vec::new();
    for using_node in using_nodes {
        if is_error_tainted(using_node) {
            continue;
        }
        let Some(resource) = collect_kinds(using_node, &["variable_declaration"])
            .into_iter()
            .next()
        else {
            continue;
        };
        let Some(body) = (if using_node.kind() == "using_statement" {
            collect_kinds(using_node, &["block"]).into_iter().next()
        } else {
            ancestors_of(using_node).find(|ancestor| ancestor.kind() == "block")
        }) else {
            continue;
        };
        for declarator in collect_kinds(resource, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            if !resource_is_disposable(root, using_node, resource, initializer, source) {
                continue;
            }
            if body_returns_resource(body, using_node, name, source) {
                issues.push(report_using(language, using_node, name, source));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2997_flags_return_of_using_resource_at_the_return_line() {
        let report = analyze_default(
            "class C\n{\n    System.IO.StreamWriter Create()\n    {\n        using (var writer = new System.IO.StreamWriter(\"app.log\"))\n        {\n            return writer;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2997");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(
            flagged[0].message,
            "Remove the 'using' statement; it will cause automatic disposal of 'writer'."
        );
    }

    #[test]
    fn s2997_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s2997_ignores_return_outside_the_using_block() {
        let report = analyze_default(
            "class C\n{\n    System.IO.StreamWriter Create()\n    {\n        using (var writer = new System.IO.StreamWriter(\"app.log\"))\n        {\n            writer.AutoFlush = true;\n        }\n        return writer;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s2997_ignores_non_disposable_initializer_and_foreign_names() {
        let literal = analyze_default(
            "class C\n{\n    string Read()\n    {\n        using (var text = \"cached\")\n        {\n            return text;\n        }\n    }\n}\n",
        );
        assert!(with_key(&literal, "csharpsquid:S2997").is_empty());

        let foreign_name = analyze_default(
            "class C\n{\n    void M()\n    {\n        var kept = new System.IO.MemoryStream();\n        using (var temp = new System.IO.MemoryStream())\n        {\n            return kept;\n        }\n    }\n}\n",
        );
        assert!(with_key(&foreign_name, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s2997_requires_a_block_body() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        using (var stream = new System.IO.MemoryStream());\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s2997_reports_two_resources_at_distinct_lines_with_explicit_types() {
        let report = analyze_default(
            "class C\n{\n    System.IO.MemoryStream First()\n    {\n        using (var a = new System.IO.MemoryStream())\n        {\n            return a;\n        }\n    }\n\n    System.IO.MemoryStream Second()\n    {\n        using (System.IO.MemoryStream b = new System.IO.MemoryStream())\n        {\n            return b;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2997");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 13);
    }

    #[test]
    fn s2997_ignores_deferred_returns_inside_nested_functions() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        using (var stream = new System.IO.MemoryStream())\n        {\n            System.Func<System.IO.Stream> later = () => stream;\n            System.IO.Stream Local() { return stream; }\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s2997_reports_one_issue_for_multiple_return_paths() {
        let report = analyze_default(
            "class C\n{\n    System.IO.Stream M(bool first)\n    {\n        using (var stream = new System.IO.MemoryStream())\n        {\n            if (first) return stream;\n            return stream;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2997").len(), 1);
    }
    #[test]
    fn s2997_flags_factory_and_using_declaration_resources() {
        let factory = analyze_default(
            "class C\n\
             {\n\
                 System.IO.Stream Create(string path)\n\
                 {\n\
                     using (var stream = System.IO.File.OpenRead(path))\n\
                     {\n\
                         return stream;\n\
                     }\n\
                 }\n\
             }\n",
        );
        assert_eq!(with_key(&factory, "csharpsquid:S2997").len(), 1);

        let declaration = analyze_default(
            "class C\n\
             {\n\
                 System.IO.Stream Create(string path)\n\
                 {\n\
                     using var stream = System.IO.File.OpenRead(path);\n\
                     return stream;\n\
                 }\n\
             }\n",
        );
        assert_eq!(with_key(&declaration, "csharpsquid:S2997").len(), 1);
    }

    #[test]
    fn s2997_resolves_disposable_aliases_but_not_transfers() {
        let report = analyze_default(
            "using StreamAlias = System.IO.Stream;\n\
             class C\n\
             {\n\
                 StreamAlias Create(string path)\n\
                 {\n\
                     using (StreamAlias stream = System.IO.File.OpenRead(path))\n\
                     {\n\
                         return Transfer(stream);\n\
                     }\n\
                 }\n\
                 static StreamAlias Transfer(StreamAlias stream) => stream;\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S2997").is_empty());
    }
}
