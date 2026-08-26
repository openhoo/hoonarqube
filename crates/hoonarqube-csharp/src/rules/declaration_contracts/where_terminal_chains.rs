use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2971 — a `Where` feeding a terminal LINQ operator folds into
/// that operator's predicate overload.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const TERMINALS: [&str; 8] = [
        "Any",
        "Count",
        "First",
        "FirstOrDefault",
        "Last",
        "LastOrDefault",
        "Single",
        "SingleOrDefault",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| TERMINALS.contains(&callee_name(*invocation, source).unwrap_or("")))
        .filter(|invocation| {
            invocation_receiver(*invocation).and_then(|receiver| callee_name(receiver, source))
                == Some("Where")
        })
        .map(|invocation| {
            issue(
                language,
                "S2971",
                "Move this filter into the terminal LINQ call's predicate.",
                range_of(invocation, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2971_flags_count_and_default_terminals() {
        let count = analyze_default(
            "class C\n{\n    int Total(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).Count();\n    }\n}\n",
        );
        assert_eq!(with_key(&count, "csharpsquid:S2971").len(), 1);

        let first_or_default = analyze_default(
            "class C\n{\n    int Head(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).FirstOrDefault();\n    }\n}\n",
        );
        assert_eq!(with_key(&first_or_default, "csharpsquid:S2971").len(), 1);
    }

    #[test]
    fn s2971_requires_where_as_immediate_receiver() {
        let interrupted = analyze_default(
            "class C\n{\n    int Total(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).Select(v => v * 2).Count();\n    }\n}\n",
        );
        assert!(with_key(&interrupted, "csharpsquid:S2971").is_empty());

        let stacked = analyze_default(
            "class C\n{\n    int Total(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).Where(v => v < 9).Count();\n    }\n}\n",
        );
        assert_eq!(with_key(&stacked, "csharpsquid:S2971").len(), 1);
    }
}
