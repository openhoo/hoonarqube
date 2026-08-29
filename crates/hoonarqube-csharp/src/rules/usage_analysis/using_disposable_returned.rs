use super::support::collect_in_callable;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use crate::rules::literals::declarator_initializer;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2997 — disposables returned from inside their own `using`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for using_statement in collect_kinds(root, &["using_statement"]) {
        if is_error_tainted(using_statement) {
            continue;
        }
        let resource = collect_kinds(using_statement, &["variable_declaration"])
            .into_iter()
            .next();
        let body = collect_kinds(using_statement, &["block"])
            .into_iter()
            .next();
        let (Some(resource), Some(body)) = (resource, body) else {
            continue;
        };
        for declarator in collect_kinds(resource, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let creates_disposable = declarator_initializer(declarator, name)
                .is_some_and(|initializer| initializer.kind() == "object_creation_expression");
            if !creates_disposable {
                continue;
            }
            let returns_variable = collect_in_callable(body, "return_statement")
                .into_iter()
                .any(|return_statement| {
                    first_named_child(return_statement).is_some_and(|expression| {
                        expression.kind() == "identifier"
                            && node_text(expression, source) == node_text(name, source)
                    })
                });
            if returns_variable {
                let keyword = collect_kinds(using_statement, &["using"])
                    .into_iter()
                    .next()
                    .unwrap_or(using_statement);
                issues.push(issue(
                    language,
                    "S2997",
                    format!(
                        "Remove the 'using' statement; it will cause automatic disposal of '{}'.",
                        node_text(name, source)
                    ),
                    range_of(keyword, source),
                ));
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
}
