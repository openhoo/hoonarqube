use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_function, receiver_chain_matches};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6607 — filtering after ordering throws away sorted work;
/// filter first.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("Where"))
        .filter(|invocation| {
            receiver_chain_matches(*invocation, source, |name| name.starts_with("OrderBy"))
        })
        .map(|invocation| {
            let ordering = collect_kinds(invocation, &["invocation_expression"])
                .into_iter()
                .filter(|candidate| candidate.id() != invocation.id())
                .find_map(|candidate| {
                    callee_name(candidate, source).filter(|name| name.starts_with("OrderBy"))
                })
                .unwrap_or("OrderBy");
            let anchor = invocation_function(invocation)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(invocation);
            issue(
                language,
                "S6607",
                format!("\"Where\" should be used before \"{ordering}\""),
                range_of(anchor, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6607_flags_filtering_after_descending_ordering() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.OrderByDescending(v => v).Where(v => v > 0);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6607").len(), 1);
    }

    #[test]
    fn s6607_counts_each_filter_after_ordering() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(v => v).Where(v => v > 0);\n        items.OrderBy(v => -v).Where(v => v < 0);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6607").len(), 2);
    }

    #[test]
    fn s6607_spares_filtering_before_ordering() {
        let report = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).OrderBy(v => v);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6607").is_empty());
    }
}
