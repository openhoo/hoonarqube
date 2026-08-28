use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{block_statements, callee_name, first_named_child};
use crate::rules::structure::{else_alternative, embedded_bodies};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3267 — a foreach whose whole body conditionally appends one
/// item is a LINQ projection in disguise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// The single `x.Add(y)` statement inside an if body, if present.
    fn lone_add_statement(if_statement: Node<'_>, source: &str) -> bool {
        let bodies = embedded_bodies(if_statement);
        match bodies.as_slice() {
            [body] => {
                let statements = if body.kind() == "block" {
                    block_statements(*body)
                } else {
                    vec![*body]
                };
                match statements.as_slice() {
                    [statement] => {
                        statement.kind() == "expression_statement"
                            && first_named_child(*statement)
                                .and_then(|expression| {
                                    (expression.kind() == "invocation_expression")
                                        .then_some(expression)
                                })
                                .and_then(|invocation| callee_name(invocation, source))
                                == Some("Add")
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    let mut issues = Vec::new();
    for foreach_statement in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(foreach_statement) || else_alternative(foreach_statement).is_some() {
            continue;
        }
        let convertible = embedded_bodies(foreach_statement)
            .first()
            .is_some_and(|body| {
                body.kind() == "block" && {
                    let statements = block_statements(*body);
                    match statements.as_slice() {
                        [only] => {
                            only.kind() == "if_statement"
                                && !is_error_tainted(*only)
                                && lone_add_statement(*only, source)
                        }
                        _ => false,
                    }
                }
            });
        if convertible {
            issues.push(issue(
                language,
                "S3267",
                "Loops should be simplified using the \"Where\" LINQ method",
                range_of(
                    foreach_statement
                        .child_by_field_name("right")
                        .unwrap_or(foreach_statement),
                    source,
                ),
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3267_flags_braceless_if_add_bodies() {
        let report = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n                result.Add(item);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3267").len(), 1);
    }

    #[test]
    fn s3267_spares_multi_statement_and_non_add_bodies() {
        let multi = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                result.Add(item);\n                result.Sort();\n            }\n        }\n    }\n}\n",
        );
        assert!(with_key(&multi, "csharpsquid:S3267").is_empty());

        let visiting = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> seen)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                Visit(item);\n            }\n        }\n    }\n}\n",
        );
        assert!(with_key(&visiting, "csharpsquid:S3267").is_empty());
    }

    #[test]
    fn s3267_counts_each_convertible_loop() {
        let report = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> evens, System.Collections.Generic.List<int> odds)\n    {\n        foreach (var item in items)\n        {\n            if (item % 2 == 0)\n            {\n                evens.Add(item);\n            }\n        }\n        foreach (var item in items)\n        {\n            if (item % 2 != 0)\n            {\n                odds.Add(item);\n            }\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3267").len(), 2);
    }
}
