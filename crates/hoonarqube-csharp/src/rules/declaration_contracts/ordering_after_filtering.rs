use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, receiver_chain_matches};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6607 — filtering after ordering throws away sorted work;
/// filter first.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| name.starts_with("OrderBy"))
        })
        .filter(|invocation| receiver_chain_matches(*invocation, source, |name| name == "Where"))
        .map(|invocation| {
            issue(
                language,
                "S6607",
                "Apply this ordering after filtering.",
                range_of(invocation, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6607_flags_descending_ordering_after_filtering() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).OrderByDescending(v => v);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6607").len(), 1);
    }

    #[test]
    fn s6607_counts_each_late_ordering_in_a_chain() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).OrderBy(v => v).OrderBy(v => -v);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6607").len(), 2);
    }

    #[test]
    fn s6607_spares_secondary_orderings() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).ThenBy(v => v);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6607").is_empty());
    }
}
