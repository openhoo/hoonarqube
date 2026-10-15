use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    callee_name, first_named_child, invocation_arguments, invocation_function,
};
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
                            node_text(literal, source).encode_utf16().count() == 3
                        })
                }
                _ => false,
            },
        )
        .map(|invocation| {
            let callee = callee_name(invocation, source).unwrap_or_default();
            let anchor = invocation_function(invocation)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(invocation);
            issue(
                language,
                "S6610",
                format!("\"{callee}\" overloads that take a \"char\" should be used"),
                range_of(anchor, source),
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

    fn ordinary_pair(value: &str) {
        for method in ["StartsWith", "EndsWith"] {
            let source = format!(
                "class C\n{{\n    bool M(string text)\n    {{\n        return text.{method}(\"{value}\");\n    }}\n}}\n"
            );
            let report = analyze_default(&source);
            let issues = with_key(&report, "csharpsquid:S6610");
            assert_eq!(issues.len(), 1, "{method}({value:?})");
            assert_eq!(
                issues[0].message,
                format!("\"{method}\" overloads that take a \"char\" should be used")
            );
            assert_eq!(issues[0].range.start.line, 5);
            assert_eq!(issues[0].range.start.column, 20);
            assert_eq!(issues[0].range.end.line, 5);
            assert_eq!(
                issues[0].range.end.column,
                20 + u32::try_from(method.len()).unwrap()
            );
            assert!(issues[0].alternatives.is_empty());
        }
    }

    #[test]
    fn s6610_original_farsi_direct_literals() {
        ordinary_pair("ی");
    }

    #[test]
    fn s6610_original_romanian_direct_literals() {
        ordinary_pair("ă");
    }

    #[test]
    fn s6610_three_byte_bmp_direct_literals() {
        ordinary_pair("字");
    }

    #[test]
    fn s6610_standalone_combining_mark_direct_literals() {
        ordinary_pair("̆");
    }

    // The actual installed analyzer qualifies all 42 cases. This bounded repair
    // preserves current native silence for the 12 positive escaped/raw/verbatim forms.
    // Keep the decomposed combining-sequence guard byte-identical to the oracle.
    #[allow(clippy::unicode_not_nfc)]
    const BOUNDARIES: &[(&str, &str, bool)] = &[
        ("ascii_StartsWith", r#"text.StartsWith("x")"#, true),
        ("ascii_EndsWith", r#"text.EndsWith("x")"#, true),
        ("farsi_StartsWith", r#"text.StartsWith("ی")"#, true),
        ("farsi_EndsWith", r#"text.EndsWith("ی")"#, true),
        ("romanian_StartsWith", r#"text.StartsWith("ă")"#, true),
        ("romanian_EndsWith", r#"text.EndsWith("ă")"#, true),
        ("cjk_StartsWith", r#"text.StartsWith("字")"#, true),
        ("cjk_EndsWith", r#"text.EndsWith("字")"#, true),
        (
            "standalone_combining_mark_StartsWith",
            r#"text.StartsWith("̆")"#,
            true,
        ),
        (
            "standalone_combining_mark_EndsWith",
            r#"text.EndsWith("̆")"#,
            true,
        ),
        ("empty_StartsWith", r#"text.StartsWith("")"#, false),
        ("empty_EndsWith", r#"text.EndsWith("")"#, false),
        (
            "multiple_ascii_StartsWith",
            r#"text.StartsWith("ab")"#,
            false,
        ),
        ("multiple_ascii_EndsWith", r#"text.EndsWith("ab")"#, false),
        ("multiple_bmp_StartsWith", r#"text.StartsWith("ăی")"#, false),
        ("multiple_bmp_EndsWith", r#"text.EndsWith("ăی")"#, false),
        (
            "supplementary_StartsWith",
            r#"text.StartsWith("😀")"#,
            false,
        ),
        ("supplementary_EndsWith", r#"text.EndsWith("😀")"#, false),
        (
            "combining_sequence_StartsWith",
            r#"text.StartsWith("ă")"#,
            false,
        ),
        (
            "combining_sequence_EndsWith",
            r#"text.EndsWith("ă")"#,
            false,
        ),
        ("escaped_ascii", r#"text.EndsWith("\u0078")"#, false),
        ("escaped_romanian", r#"text.EndsWith("\u0103")"#, false),
        ("escaped_farsi", r#"text.EndsWith("\u06CC")"#, false),
        ("escaped_hex_bmp", r#"text.EndsWith("\x0103")"#, false),
        ("escaped_big_u_bmp", r#"text.EndsWith("\U00000103")"#, false),
        ("escaped_short_newline", r#"text.EndsWith("\n")"#, false),
        (
            "escaped_supplementary",
            r#"text.EndsWith("\U0001F600")"#,
            false,
        ),
        (
            "escaped_surrogate_pair",
            r#"text.EndsWith("\uD83D\uDE00")"#,
            false,
        ),
        (
            "escaped_combining_sequence",
            r#"text.EndsWith("a\u0306")"#,
            false,
        ),
        ("raw_ascii", r#"text.EndsWith("""x""")"#, false),
        ("raw_romanian", r#"text.EndsWith("""ă""")"#, false),
        ("raw_cjk", r#"text.EndsWith("""字""")"#, false),
        ("verbatim_ascii", r#"text.EndsWith(@"x")"#, false),
        ("verbatim_romanian", r#"text.EndsWith(@"ă")"#, false),
        ("verbatim_farsi", r#"text.EndsWith(@"ی")"#, false),
        ("char_ascii", "text.EndsWith('x')", false),
        ("char_romanian", "text.EndsWith('ă')", false),
        ("char_cjk", "text.EndsWith('字')", false),
        (
            "comparison_two_StartsWith",
            r#"text.StartsWith("ă", StringComparison.Ordinal)"#,
            false,
        ),
        (
            "comparison_three_StartsWith",
            r#"text.StartsWith("ă", false, System.Globalization.CultureInfo.InvariantCulture)"#,
            false,
        ),
        (
            "comparison_two_EndsWith",
            r#"text.EndsWith("ă", StringComparison.Ordinal)"#,
            false,
        ),
        (
            "comparison_three_EndsWith",
            r#"text.EndsWith("ă", false, System.Globalization.CultureInfo.InvariantCulture)"#,
            false,
        ),
    ];

    fn boundary_matrix(unicode_crlf: bool) {
        let mut failures = Vec::new();
        for &(name, expression, positive) in BOUNDARIES {
            let prefix = if unicode_crlf {
                "/* 😀 café */ "
            } else {
                ""
            };
            let mut source = format!(
                "using System;\nclass C\n{{\n    bool M(string text)\n    {{\n        {prefix}return {expression};\n    }}\n}}\n"
            );
            if unicode_crlf {
                source = source.replace('\n', "\r\n");
            }
            let report = analyze_default(&source);
            let issues = with_key(&report, "csharpsquid:S6610");
            if issues.len() != usize::from(positive) {
                failures.push(format!(
                    "{name}: expected {}, actual {}",
                    usize::from(positive),
                    issues.len()
                ));
            }
            if positive && issues.len() == 1 {
                let method = if expression.contains(".StartsWith(") {
                    "StartsWith"
                } else {
                    "EndsWith"
                };
                let column = if unicode_crlf { 33 } else { 20 };
                assert_eq!(
                    issues[0].message,
                    format!("\"{method}\" overloads that take a \"char\" should be used")
                );
                assert_eq!(issues[0].range.start.line, 6);
                assert_eq!(issues[0].range.start.column, column);
                assert_eq!(issues[0].range.end.line, 6);
                assert_eq!(
                    issues[0].range.end.column,
                    column + u32::try_from(method.len()).unwrap()
                );
                assert!(issues[0].alternatives.is_empty());
            }
        }
        assert!(failures.is_empty(), "all 42 boundaries: {failures:#?}");
    }

    #[test]
    fn s6610_all_42_literal_and_guard_boundaries_lf() {
        boundary_matrix(false);
    }

    #[test]
    fn s6610_all_42_literal_and_guard_boundaries_unicode_crlf() {
        boundary_matrix(true);
    }
}
