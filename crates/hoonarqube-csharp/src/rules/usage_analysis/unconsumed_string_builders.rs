use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, invocation_function};
use crate::rules::literals::declarator_initializer;
use crate::symbol_table::UsageSymbols;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3063 — builders nobody ever turns into output.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        if is_error_tainted(declarator) {
            continue;
        }
        let container = declarator
            .parent()
            .and_then(|declaration| declaration.parent());
        if matches!(container, Some(container) if matches!(container.kind(), "field_declaration" | "event_field_declaration"))
        {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let builds_content = declarator_initializer(declarator, name).is_some_and(|initializer| {
            initializer
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "StringBuilder"
                })
        });
        if !builds_content {
            continue;
        }
        let uses: Vec<Node> = symbols
            .uses_of(node_text(name, source))
            .into_iter()
            .filter(|use_site| use_site.byte_range().start > declarator.byte_range().end)
            .collect();
        if uses.is_empty()
            || uses
                .iter()
                .any(|use_site| consumes_string_builder(*use_site, source))
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3063",
            format!(
                "The content of StringBuilder '{}' is never consumed.",
                node_text(name, source)
            ),
            range_of(declarator),
        ));
    }
    issues
}

/// `StringBuilder` members that mutate instead of yielding content.
const STRING_BUILDER_MUTATIONS: [&str; 7] = [
    "Append",
    "AppendLine",
    "AppendFormat",
    "Insert",
    "Remove",
    "Clear",
    "Replace",
];

/// Whether a reference reads a builder's content instead of mutating it.
fn consumes_string_builder(reference: Node<'_>, source: &str) -> bool {
    let Some(parent) = reference.parent() else {
        return true;
    };
    let invocation = parent.parent().filter(|grandparent| {
        parent.kind() == "member_access_expression"
            && grandparent.kind() == "invocation_expression"
            && invocation_function(*grandparent)
                .is_some_and(|function| function.id() == parent.id())
    });
    if let Some(invocation) = invocation {
        return !callee_name(invocation, source)
            .is_some_and(|callee| STRING_BUILDER_MUTATIONS.contains(&callee));
    }
    matches!(
        parent.kind(),
        "argument" | "return_statement" | "element_access_expression"
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3063_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3063").is_empty());
    }

    #[test]
    fn s3063_flags_mutated_builder_at_the_declarator_line() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var message = new System.Text.StringBuilder();\n        message.Append(\"hi\");\n        message.Remove(0, 1);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3063");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(
            flagged[0].message,
            "The content of StringBuilder 'message' is never consumed."
        );
    }

    #[test]
    fn s3063_ignores_never_used_builders() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var orphan = new System.Text.StringBuilder();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3063").is_empty());
    }

    #[test]
    fn s3063_ignores_builders_declared_as_fields() {
        let report = analyze_default(
            "class C\n{\n    System.Text.StringBuilder buffer = new System.Text.StringBuilder();\n\n    void M()\n    {\n        buffer.Append(\"x\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3063").is_empty());
    }

    #[test]
    fn s3063_accepts_argument_return_and_element_access_consumption() {
        let argument = analyze_default(
            "class C\n{\n    void M()\n    {\n        var b = new StringBuilder();\n        b.Append(\"x\");\n        Store(b);\n    }\n}\n",
        );
        assert!(with_key(&argument, "csharpsquid:S3063").is_empty());

        let returned = analyze_default(
            "class C\n{\n    StringBuilder M()\n    {\n        var b = new StringBuilder();\n        b.Append(\"x\");\n        return b;\n    }\n}\n",
        );
        assert!(with_key(&returned, "csharpsquid:S3063").is_empty());

        let element_access = analyze_default(
            "class C\n{\n    char M()\n    {\n        var b = new StringBuilder(\"abc\");\n        return b[0];\n    }\n}\n",
        );
        assert!(with_key(&element_access, "csharpsquid:S3063").is_empty());
    }

    #[test]
    fn s3063_reports_two_violations_at_distinct_lines_with_explicit_types() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        var first = new StringBuilder();\n        StringBuilder second = new StringBuilder(\"s\");\n        first.Append(1);\n        second.Insert(0, 'a');\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3063");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }
}
