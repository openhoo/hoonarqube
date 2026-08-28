use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_function, is_test_attributed};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2699 — test methods without assertions verify nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let asserts = collect_kinds(body, &["invocation_expression"])
            .iter()
            .any(|invocation| looks_like_assertion(*invocation, source));
        if !asserts {
            let name = method.child_by_field_name("name").unwrap_or(method);
            issues.push(issue(
                language,
                "S2699",
                "Add at least one assertion to this test case.",
                range_of(name, source),
            ));
        }
    }
    issues
}

/// Whether the invocation reads like an assertion call.
fn looks_like_assertion(invocation: Node<'_>, source: &str) -> bool {
    let Some(function) = invocation_function(invocation) else {
        return false;
    };
    let spelled = node_text(function, source).trim();
    spelled.contains("Assert")
        || callee_name(invocation, source).is_some_and(|name| {
            ["Should", "Verify", "Expect", "Check", "That"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2699_accepts_fluent_and_verify_style_assertions() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    public void UsesFluent()\n    {\n        var result = Compute();\n        result.Should().Be(2);\n    }\n\n    [Fact]\n    public void UsesVerify()\n    {\n        service.Verify(it => it.Flush());\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2699").is_empty());
    }

    #[test]
    fn s2699_flags_plain_helper_calls_and_counts_each_test() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    public void First()\n    {\n        repository.Flush();\n        log.Info(\"done\");\n    }\n\n    [Fact]\n    public void Second()\n    {\n        calculator.Total();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2699");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 11);
    }
}
