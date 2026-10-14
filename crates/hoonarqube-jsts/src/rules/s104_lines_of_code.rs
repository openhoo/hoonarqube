// Rule module s104_lines_of_code (generated).

use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::Statement;
use oxc_span::GetSpan;

fn check_too_many_lines_of_code(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    // Same notion of code lines as `file_metrics`: statement coverage
    // excludes blank lines and pure-comment lines. Counted over merged
    // coverage intervals rather than a per-line set.
    let count = index.covered_line_count(body.iter().map(GetSpan::span));
    let maximum = usize::try_from(rules.maximum_lines_of_code).unwrap_or(usize::MAX);
    if count <= maximum {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S104", language.prefix()),
        message: format!(
            "This file has {} lines of code, which is greater than {} authorized. \
             Split it into smaller pieces.",
            count, rules.maximum_lines_of_code
        ),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    }]
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_too_many_lines_of_code(
        ctx.program.body.as_slice(),
        ctx.index,
        ctx.language,
        ctx.rules,
    )
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn lines_of_code_counts_statements_not_blank_or_comment_lines() {
        let rules = RuleOptions {
            maximum_lines_of_code: 2,
            ..RuleOptions::default()
        };
        // Four physical lines, but only two code lines: within the threshold.
        let within = keys_with_rules("let a = 1;\n\n// filler\nlet b = 2;\n", &rules);
        assert_eq!(count_key(&within, "javascript:S104"), 0);

        // Blank and comment lines still do not count toward three statements.
        let over = keys_with_rules(
            "let a = 1;\n\n// filler\nlet b = 2;\n\n// filler\nlet c = 3;\n",
            &rules,
        );
        assert_eq!(count_key(&over, "javascript:S104"), 1);
    }

    fn s104_findings(
        source: &str,
        language: JstsLanguage,
        maximum: u32,
    ) -> Vec<hoonarqube_ir::Issue> {
        analyze(
            PathBuf::from(match language {
                JstsLanguage::JavaScript => "case.js",
                JstsLanguage::TypeScript => "case.ts",
            }),
            source,
            language,
            &AnalyzerOptions {
                maximum_lines_of_code: maximum,
                ..no_header_options()
            },
        )
        .issues
        .into_iter()
        .filter(|finding| finding.rule_key.ends_with(":S104"))
        .collect()
    }

    fn s104_expected(language: JstsLanguage, count: u32, maximum: u32) -> hoonarqube_ir::Issue {
        issue(
            &format!("{}:S104", language.prefix()),
            &format!(
                "This file has {count} lines, which is greater than {maximum} authorized. Split it into smaller files."
            ),
            (0, 0),
            (0, 0),
        )
    }

    fn s104_reference_shapes(language: JstsLanguage) {
        // Exact source shapes qualified by the retained 18-file real scanner
        // capture. Counts are independently fixed by those eight raw issues.
        let prefix = "tick();\n".repeat(997);
        for (name, suffix, expected) in [
            ("over", "tick();\ntick();\ntick();\ntick();\n", true),
            ("within", "tick();\ntick();\ntick();\n", false),
            (
                "block_blank",
                "function example() {\n\n// comment\nreturn 1;\n}\n",
                false,
            ),
            (
                "header",
                "/* comment\n * comment\n */\ntick();\ntick();\n",
                false,
            ),
            (
                "inline",
                "tick(); // one\ntick(); // two\ntick(); // three\ntick(); // four\n",
                true,
            ),
            (
                "block_only",
                "/* comment\n * comment\n */\ntick();\n",
                false,
            ),
            ("template", "const text = `first\n\nmiddle\nlast`;\n", false),
            (
                "multiple_comments",
                "/*one*/ /*two*/\ntick();\ntick();\ntick();\n",
                true,
            ),
            (
                "crlf",
                "const café = 1;\r\n\r\n// comment\r\ntick();\r\ntick();\r\ntick();\r\n",
                true,
            ),
        ] {
            let findings = s104_findings(&(prefix.clone() + suffix), language, 1000);
            assert_eq!(
                findings,
                if expected {
                    vec![s104_expected(language, 1001, 1000)]
                } else {
                    Vec::new()
                },
                "{name}"
            );
        }
    }

    #[test]
    fn s104_javascript_reference_shapes_have_exact_file_level_issues() {
        s104_reference_shapes(JstsLanguage::JavaScript);
    }

    #[test]
    fn s104_typescript_reference_shapes_have_exact_file_level_issues() {
        s104_reference_shapes(JstsLanguage::TypeScript);
    }

    #[test]
    fn s104_function_blanks_and_comments_do_not_consume_budget() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            assert!(
                s104_findings("function f() {\n\n// comment\nreturn 1;\n}\n", language, 3)
                    .is_empty()
            );
        }
    }

    #[test]
    fn s104_template_blank_lines_do_not_consume_budget() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            assert!(
                s104_findings("const text = `first\n\nmiddle\nlast`;\n", language, 3).is_empty()
            );
        }
    }

    #[test]
    fn s104_last_comment_per_line_matches_installed_reference_helper() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            // The reference maps the LAST comment to the row. Its prefix
            // contains the first comment, so this otherwise comment-only row
            // counts. A union-of-comment-coverage calculation is incompatible.
            assert_eq!(
                s104_findings("/*one*/ /*two*/\ntick();\n", language, 1),
                vec![s104_expected(language, 2, 1)]
            );
        }
    }

    #[test]
    fn s104_configured_budget_equality_and_excess_are_exact() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            let source = "/* leading\n comment */\ntick(); // inline\n\ntick();\n";
            assert!(s104_findings(source, language, 2).is_empty());
            assert_eq!(
                s104_findings(source, language, 1),
                vec![s104_expected(language, 2, 1)]
            );
        }
    }

    #[test]
    fn s104_unicode_and_ecmascript_line_terminators_preserve_local_count() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            for separator in ["\n", "\r\n", "\r", "\u{2028}", "\u{2029}"] {
                let source = [
                    "const café = 1;",
                    "",
                    "/* ü */",
                    "tick();",
                    "// comment",
                    "tick();",
                ]
                .join(separator);
                assert!(s104_findings(&source, language, 3).is_empty());
                assert_eq!(
                    s104_findings(&source, language, 2),
                    vec![s104_expected(language, 3, 2)]
                );
            }
        }
    }

    #[test]
    fn s104_literal_comment_markers_are_not_parser_comments() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            let source = "const text = `first\n// literal text\n/* literal text */\nlast`;\n";
            assert!(s104_findings(source, language, 4).is_empty());
            assert_eq!(
                s104_findings(source, language, 3),
                vec![s104_expected(language, 4, 3)]
            );
        }
    }

    #[test]
    fn s104_empty_and_single_comment_only_files_stay_clean_at_zero_budget() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            for source in [
                "",
                "\n// one\n\n",
                "/* comment\n * comment\n */\n",
                "\u{feff}\u{a0}\n",
            ] {
                assert!(s104_findings(source, language, 0).is_empty(), "{source:?}");
            }
        }
    }

    #[test]
    fn s104_local_count_preserves_existing_statement_span_metrics() {
        let source = "function f() {\n\n// comment\nreturn 1;\n}\n";
        let report = js(source);
        assert_eq!(report.metrics.code_lines, 5);
        assert!(s104_findings(source, JstsLanguage::JavaScript, 3).is_empty());
    }
}
