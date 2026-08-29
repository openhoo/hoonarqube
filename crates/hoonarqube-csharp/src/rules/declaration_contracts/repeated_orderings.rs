use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_function, receiver_chain_matches};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3169 — stacking orderings re-sorts the same sequence.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("OrderBy" | "OrderByDescending")
            )
        })
        .filter(|invocation| {
            receiver_chain_matches(*invocation, source, |name| {
                matches!(name, "OrderBy" | "OrderByDescending")
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S3169",
                "Use 'ThenBy' instead.",
                range_of(
                    invocation_function(invocation)
                        .and_then(|function| function.child_by_field_name("name"))
                        .unwrap_or(invocation),
                    source,
                ),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3169_counts_inner_links_of_triple_orderings() {
        let report = analyze_default(
            "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a).OrderBy(b => b).OrderBy(c => c);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3169").len(), 2);
    }

    #[test]
    fn s3169_flags_descending_restacks() {
        let report = analyze_default(
            "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a).OrderByDescending(b => b);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3169").len(), 1);
    }

    #[test]
    fn s3169_spares_orderings_after_other_operators() {
        let report = analyze_default(
            "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.GroupBy(a => a).OrderBy(b => b);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3169").is_empty());
    }
}
