use super::support::{enclosing_callable, operator_of};
use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S881 — increments and decrements stay standalone.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["prefix_unary_expression", "postfix_unary_expression"];
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &KINDS) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("++" | "--")) {
            continue;
        }
        let callable = enclosing_callable(unary).map(|owner| owner.id());
        let mixed = ancestors_of(unary)
            .take_while(|ancestor| {
                !matches!(ancestor.kind(), "expression_statement" | "for_statement")
                    && Some(ancestor.id()) != callable
            })
            .any(|ancestor| {
                matches!(
                    ancestor.kind(),
                    "binary_expression" | "conditional_expression" | "invocation_expression"
                )
            });
        if !mixed {
            continue;
        }
        let mut cursor = unary.walk();
        let operator = unary
            .children(&mut cursor)
            .find(|child| matches!(child.kind(), "++" | "--"))
            .unwrap_or(unary);
        let operation = if operator.kind() == "--" {
            "decrement"
        } else {
            "increment"
        };
        issues.push(issue(
            language,
            "S881",
            format!("Extract this {operation} operation into a dedicated statement."),
            range_of(operator, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s881_minimal_type_has_no_findings() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_standalone_and_for_clause_updates_stay_clean() {
        let report = analyze_default(
            "class C\n{\n    void M(int n)\n    {\n        int i = 0;\n        i++;\n        i--;\n        for (var j = 0; j < n; j++)\n        {\n            Step(i);\n        }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_flags_embedded_prefix_and_postfix_updates() {
        let report = analyze_default(
            "class C\n{\n    int M(int i)\n    {\n        var first = i++ + 1;\n        Consume(--first);\n        return first;\n    }\n}\n",
        );
        let issues = with_key(&report, "csharpsquid:S881");
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start.line, 5);
        assert_eq!(issues[1].range.start.line, 6);
    }

    #[test]
    fn s881_spares_updates_used_only_as_assignment_values() {
        let report = analyze_default(
            "class C\n{\n    int M(int i)\n    {\n        var first = i++;\n        return --first;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }

    #[test]
    fn s881_does_not_mix_lambda_body_with_outer_invocation() {
        let report = analyze_default(
            "class C { void M(int i) { Consume(() => i++); Consume(delegate { return --i; }); } }",
        );
        assert!(with_key(&report, "csharpsquid:S881").is_empty());
    }
}
