use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{invocation_arguments, invocation_targets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2970 — a constraint-less `Assert.That` asserts nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_targets(*call, source, Some("Assert"), &["That"]))
        .filter(|call| invocation_arguments(*call).len() == 1)
        .map(|call| {
            issue(
                language,
                "S2970",
                "Complete this 'Assert.That' with a constraint.",
                range_of(call, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2970_counts_each_single_argument_assert_that() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.That(flag);\n        if (ready)\n        {\n            Assert.That(state);\n        }\n        Check.That(other);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2970");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 8); // document line 7
    }
}
