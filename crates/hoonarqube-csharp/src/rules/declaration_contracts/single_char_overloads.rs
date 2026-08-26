use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6610 — one-character string arguments have a char-based
/// `StartsWith`/`EndsWith` overload without allocation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("StartsWith" | "EndsWith")
            )
        })
        .filter(
            |invocation| match invocation_arguments(*invocation).as_slice() {
                [only] => {
                    let literal = first_named_child(*only);
                    literal.is_some_and(|literal| literal.kind() == "string_literal")
                        && literal.is_some_and(|literal| {
                            node_text(literal, source).len() == "\"c\"".len()
                        })
                }
                _ => false,
            },
        )
        .map(|invocation| {
            issue(
                language,
                "S6610",
                "Call the char-based overload with this single character.",
                range_of(invocation, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6610_flags_endswith_single_characters() {
        let report = analyze_default(
            "class C\n{\n    bool Tail(string s)\n    {\n        return s.EndsWith(\"x\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6610").len(), 1);
    }

    #[test]
    fn s6610_spares_char_literals_and_empty_strings() {
        let character = analyze_default(
            "class C\n{\n    bool Head(string s)\n    {\n        return s.StartsWith('a');\n    }\n}\n",
        );
        assert!(with_key(&character, "csharpsquid:S6610").is_empty());

        let empty = analyze_default(
            "class C\n{\n    bool Head(string s)\n    {\n        return s.StartsWith(\"\");\n    }\n}\n",
        );
        assert!(with_key(&empty, "csharpsquid:S6610").is_empty());
    }

    #[test]
    fn s6610_spares_comparison_argument_overloads() {
        let report = analyze_default(
            "class C\n{\n    bool Head(string s)\n    {\n        return s.StartsWith(\"a\", System.StringComparison.Ordinal);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6610").is_empty());
    }
}
