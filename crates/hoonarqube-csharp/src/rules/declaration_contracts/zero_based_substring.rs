use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4635 — search directly with a start-index overload instead of
/// allocating a substring for one search.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            SEARCH_METHODS.contains(&callee_name(*invocation, source).unwrap_or(""))
        })
        .filter(|invocation| {
            invocation_receiver(*invocation).is_some_and(|receiver| {
                receiver.kind() == "invocation_expression"
                    && callee_name(receiver, source) == Some("Substring")
                    && invocation_arguments(receiver).len() == 1
            })
        })
        .map(|invocation| {
            let method = callee_name(invocation, source).unwrap_or("search");
            issue(
                language,
                "S4635",
                format!(
                    "Replace '{method}' with the overload that accepts a startIndex parameter."
                ),
                range_of(invocation, source),
            )
        })
        .collect()
}

const SEARCH_METHODS: [&str; 4] = ["IndexOf", "IndexOfAny", "LastIndexOf", "LastIndexOfAny"];
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4635_flags_substring_then_search() {
        let report = analyze_default(
            "class C\n{\n    int Find(string s, int start)\n    {\n        return s.Substring(start).IndexOf('x');\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4635").len(), 1);
    }

    #[test]
    fn s4635_counts_each_substring_search_chain() {
        let report = analyze_default(
            "class C\n{\n    int Parts(string s, int start)\n    {\n        return s.Substring(start).IndexOf('x') + s.Substring(start).LastIndexOf('y');\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4635").len(), 2);
    }

    #[test]
    fn s4635_spares_substrings_not_used_for_search() {
        let report = analyze_default(
            "class C\n{\n    string Slice(string s, int start)\n    {\n        return s.Substring(start, 3);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4635").is_empty());
    }
}
