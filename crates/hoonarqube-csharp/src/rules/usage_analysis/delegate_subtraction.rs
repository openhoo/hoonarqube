use super::support::{enclosing_callable, typed_variables};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3172 — delegate subtraction hides removed handlers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let delegates = declared_delegate_names(root, source);
    let mut issues = Vec::new();
    for binary in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(binary) || operator_of(binary) != Some("-") {
            continue;
        }
        let Some((left, right)) = binary_operands(binary) else {
            continue;
        };
        if left.kind() != "identifier"
            || !collect_kinds(right, &["binary_expression"])
                .into_iter()
                .any(|chain| operator_of(chain) == Some("+"))
        {
            continue;
        }
        let name = node_text(left, source);
        let delegate_typed = enclosing_callable(binary)
            .into_iter()
            .flat_map(|scope| typed_variables(scope, source))
            .filter(|(variable, _)| *variable == name)
            .any(|(_, type_name)| is_delegate_type_name(Some(type_name), &delegates));
        if delegate_typed {
            issues.push(issue(
                language,
                "S3172",
                "Review this subtraction of a chain of delegates: it may not work as you expect.",
                range_of(binary, source),
            ));
        }
    }
    issues
}

/// Delegate type names declared in the file.
fn declared_delegate_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    collect_kinds(root, &["delegate_declaration"])
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}

/// Whether a declared type spells a delegate: in-file delegates or common
/// handler suffixes.
fn is_delegate_type_name(
    type_name: Option<&str>,
    delegates: &std::collections::HashSet<&str>,
) -> bool {
    type_name.is_some_and(|name| {
        delegates.contains(name)
            || name.ends_with("Delegate")
            || name.ends_with("Handler")
            || name.ends_with("Callback")
            || name.ends_with("EventHandler")
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3172_matches_handler_suffix_types() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        FooHandler first = FooHandler.Empty;\n        FooHandler second = FooHandler.Empty;\n        FooHandler pipeline = first + second;\n        var trimmed = pipeline - (first + second);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3172");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);
    }

    #[test]
    fn s3172_ignores_integer_subtraction() {
        let report = analyze_default(
            "class C\n{\n    int Diff(int left, int right)\n    {\n        return left - right;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3172").is_empty());
    }

    #[test]
    fn s3172_leaves_compound_unsubscribes_alone() {
        let report = analyze_default(
            "class C\n{\n    delegate void Handler();\n    void M()\n    {\n        Handler current = null;\n        current -= current;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3172").is_empty());
    }

    #[test]
    fn s3172_requires_named_right_operand() {
        let report = analyze_default(
            "class C\n{\n    delegate void Handler();\n    void M()\n    {\n        Handler current = null;\n        var next = current - null;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3172").is_empty());
    }

    #[test]
    fn s3172_reports_each_delegate_subtraction_distinctly() {
        let report = analyze_default(
            "class C\n{\n    delegate void Handler();\n    void M()\n    {\n        Handler alpha = null;\n        Handler beta = null;\n        Handler gamma = null;\n        var first = alpha - (beta + gamma);\n        var second = beta - (alpha + gamma);\n    }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S3172")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![9, 10]);
    }

    #[test]
    fn s3172_does_not_leak_delegate_types_between_methods() {
        let report = analyze_default(
            "class C\n{\n    void Delegates()\n    {\n        Handler pipeline = null;\n        var trimmed = pipeline - (pipeline + pipeline);\n    }\n\n    int Numbers()\n    {\n        int pipeline = 4;\n        return pipeline - (pipeline + pipeline);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3172");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
