use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_function};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2970 — a constraint-less `Assert.That` asserts nothing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            matches!(callee_name(*call, source), Some("That" | "Should"))
                && invocation_arguments(*call).len()
                    == usize::from(callee_name(*call, source) == Some("That"))
        })
        .filter(|call| {
            !call.parent().is_some_and(|parent| {
                parent.kind() == "member_access_expression"
                    && parent
                        .parent()
                        .is_some_and(|grandparent| grandparent.kind() == "invocation_expression")
            })
        })
        .filter_map(|call| {
            let function = invocation_function(call)?;
            let method = function.child_by_field_name("name").unwrap_or(function);
            issue(
                language,
                "S2970",
                "Complete the assertion",
                range_of(method, source),
            )
            .into()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2970_counts_each_single_argument_assert_that() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        NFluent.Check.That(flag);\n        if (ready)\n        {\n            NFluent.Check.That(state);\n        }\n        NFluent.Check.That(other).IsEqualTo(other);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2970");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 8); // document line 7
        assert_eq!(flagged[0].message, "Complete the assertion");
    }
}
