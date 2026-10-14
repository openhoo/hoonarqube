// Rule module s1451_file_header (generated).

use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{MAX_GROUP_DEPTH, regex_prefix_match};
use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_regular_expression::{ConstructorParser, Options};

/// Validate only bounded configurations and qualified syntax failures. Oxc's
/// numeric limits can reject patterns accepted by the embedded Node runtime, and
/// its diagnostics have no typed syntax/resource distinction. Unknown results
/// therefore retain the existing matcher behavior.
fn definitely_invalid_header_regex(pattern: &str) -> bool {
    const MAX_VALIDATION_BYTES: usize = 4096;
    // Counting every opening parenthesis, even escaped ones and class members,
    // conservatively bounds recursive group depth without parsing the pattern.
    if pattern.len() > MAX_VALIDATION_BYTES
        || pattern.bytes().filter(|byte| *byte == b'(').count() > MAX_GROUP_DEPTH as usize
    {
        return false;
    }
    let Ok(quoted_pattern) = serde_json::to_string(pattern) else {
        return false;
    };
    let allocator = Allocator::default();
    let Err(diagnostic) = ConstructorParser::new(
        &allocator,
        &quoted_pattern,
        Some("\"s\""),
        Options::default(),
    )
    .parse() else {
        return false;
    };
    // Exact categories are qualified against the pinned Node constructor,
    // including legacy escapes and Annex B quantifiable lookahead assertions.
    // In particular, "Number is too large" is never proof of invalid syntax.
    matches!(
        diagnostic.message.as_ref(),
        "Invalid regular expression: Invalid braced quantifier"
            | "Invalid regular expression: Unterminated capturing group"
            | "Invalid regular expression: Unterminated ignore group"
            | "Invalid regular expression: Unterminated character class"
            | "Invalid regular expression: Invalid extended atom escape"
    )
}

fn check_file_header(source: &str, language: JstsLanguage, rules: &RuleOptions) -> Vec<Issue> {
    let header_present = if rules.header_is_regular_expression {
        // SonarJS returns no visitor when RegExp compilation fails. Retain the
        // established empty-regex behavior and suppress only definite errors.
        if rules.header_format.is_empty() || definitely_invalid_header_regex(&rules.header_format) {
            return Vec::new();
        }
        regex_prefix_match(&rules.header_format, source)
    } else {
        // `SonarJS` splits `headerFormat` into expected lines and compares
        // each physical line exactly. An empty format therefore expects one
        // empty line and fires whenever line 1 is non-empty.
        // Java's `split('\n')` drops trailing empty strings, so a trailing
        // newline in the format does not add an expected empty line.
        let mut expected: Vec<&str> = rules.header_format.split('\n').collect();
        while expected.last().is_some_and(|line| line.is_empty()) && expected.len() > 1 {
            expected.pop();
        }
        let mut lines = source.lines();
        expected.iter().all(|expected_line| {
            lines
                .next()
                .is_some_and(|line| line.trim_end_matches('\r') == *expected_line)
        })
    };
    if header_present {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S1451", language.prefix()),
        message: "Add or update the header of this file.".to_string(),
        range: hoonarqube_ir::Range::file_level(),
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    }]
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_file_header(ctx.source, ctx.language, ctx.rules)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    fn header_regex_report(
        language: JstsLanguage,
        pattern: &str,
        regular_expression: bool,
        source: &str,
        expected: usize,
    ) -> hoonarqube_ir::FileReport {
        let path = match language {
            JstsLanguage::JavaScript => "case.js",
            JstsLanguage::TypeScript => "case.ts",
        };
        let options = AnalyzerOptions {
            header_format: pattern.to_owned(),
            header_is_regular_expression: regular_expression,
            ..AnalyzerOptions::default()
        };
        let report = crate::analyze(PathBuf::from(path), source, language, &options);
        let count = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1451"))
            .count();
        assert_eq!(count, expected, "{language:?}: {pattern:?}");
        report
    }

    fn without_header(mut report: hoonarqube_ir::FileReport) -> serde_json::Value {
        report
            .issues
            .retain(|issue| !issue.rule_key.ends_with(":S1451"));
        serde_json::to_value(report).expect("serialize public file report")
    }

    fn assert_invalid_regex_controls(language: JstsLanguage) {
        let source = "const value = 1;\n";
        let baseline = without_header(header_regex_report(language, "", true, source, 0));
        for pattern in ["*", "(", "[", "\\", "+", "?", "a++", "(?:", "[a", "a\\"] {
            let report = header_regex_report(language, pattern, true, source, 0);
            assert_eq!(without_header(report), baseline);
        }
    }

    #[test]
    fn s1451_configured_regex_invalid_syntax_javascript() {
        assert_invalid_regex_controls(JstsLanguage::JavaScript);
    }

    #[test]
    fn s1451_configured_regex_invalid_syntax_typescript() {
        assert_invalid_regex_controls(JstsLanguage::TypeScript);
    }

    #[test]
    fn s1451_configured_regex_keeps_valid_and_unknown_patterns_positive() {
        let source = "const value = 1;\n";
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            let baseline = without_header(header_regex_report(language, "", true, source, 0));
            for pattern in [
                "^// License",
                "^(?=// License)// License",
                "(?<=// )License",
                "a{9007199254740992}",
                "a{18446744073709551616}",
                "a{2,1}",
                "(?q:a)",
                "[z-a]",
            ] {
                let report = header_regex_report(language, pattern, true, source, 1);
                assert_eq!(without_header(report), baseline);
                assert_file_level_header(&header_regex_report(language, pattern, true, source, 1));
            }
        }
    }

    #[test]
    fn s1451_configured_regex_sequencing_preserves_literal_and_matching_controls() {
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            for (pattern, regular_expression, source, expected) in [
                ("*", true, "const value = 1;\n", 0),
                ("*", true, "const value = 1;\n", 0),
                ("^// License", true, "// License\nconst value = 1;\n", 0),
                ("^// License", true, "const value = 1;\n", 1),
                ("*", false, "const value = 1;\n", 1),
                ("", true, "const value = 1;\n", 0),
                // Valid lookahead matching remains unsupported by the matcher.
                (
                    "^(?=// License)// License",
                    true,
                    "// License\nconst value = 1;\n",
                    1,
                ),
            ] {
                header_regex_report(language, pattern, regular_expression, source, expected);
            }
        }
    }

    #[test]
    fn s1451_configured_regex_validation_guards_retain_existing_behavior() {
        let oversized = format!("*{}", "a".repeat(4096));
        let deep = format!("{}*{}", "(".repeat(49), ")".repeat(49));
        let wide = "(*)".repeat(49);
        let at_byte_limit = format!("*{}", "a".repeat(4095));
        let at_group_limit = format!("{}*{}", "(".repeat(48), ")".repeat(48));
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            for pattern in [&oversized, &deep, &wide] {
                let report = header_regex_report(language, pattern, true, "const value = 1;\n", 1);
                assert_file_level_header(&report);
            }
            for pattern in [&at_byte_limit, &at_group_limit] {
                header_regex_report(language, pattern, true, "const value = 1;\n", 0);
            }
        }
    }

    fn assert_file_level_header(report: &hoonarqube_ir::FileReport) {
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1451"))
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range, hoonarqube_ir::Range::file_level());
        assert_eq!(
            findings[0].message,
            "Add or update the header of this file."
        );
        assert!(findings[0].fix.is_none());
        assert!(findings[0].alternatives.is_empty());
        assert!(findings[0].flows.is_empty());
    }

    #[test]
    fn s1451_file_level_default_identity_preserves_clean_controls() {
        for (path, language) in [
            ("case.js", JstsLanguage::JavaScript),
            ("case.ts", JstsLanguage::TypeScript),
        ] {
            let options = AnalyzerOptions::default();
            let missing = crate::analyze(
                PathBuf::from(path),
                "const value = 1;\n",
                language,
                &options,
            );
            assert_file_level_header(&missing);
            let clean = crate::analyze(
                PathBuf::from(path),
                "\nconst value = 1;\n",
                language,
                &options,
            );
            assert_eq!(
                count_key(
                    &report_keys(&clean),
                    &format!("{}:S1451", language.prefix())
                ),
                0
            );
        }
    }

    #[test]
    fn s1451_file_level_configured_identity_preserves_literal_and_regex_controls() {
        for (path, language) in [
            ("case.js", JstsLanguage::JavaScript),
            ("case.ts", JstsLanguage::TypeScript),
        ] {
            for (header, regular_expression, good) in [
                ("// Copyright", false, "// Copyright\nconst value = 1;\n"),
                (
                    r"^// \(c\) \d{4}",
                    true,
                    "// (c) 2026 ACME\nconst value = 1;\n",
                ),
            ] {
                let options = AnalyzerOptions {
                    header_format: header.to_owned(),
                    header_is_regular_expression: regular_expression,
                    ..AnalyzerOptions::default()
                };
                let missing = crate::analyze(
                    PathBuf::from(path),
                    "const value = 1;\n",
                    language,
                    &options,
                );
                assert_file_level_header(&missing);
                let clean = crate::analyze(PathBuf::from(path), good, language, &options);
                assert_eq!(
                    count_key(
                        &report_keys(&clean),
                        &format!("{}:S1451", language.prefix())
                    ),
                    0
                );
            }
        }
    }

    #[test]
    fn s1451_file_level_change_preserves_existing_detection_policies() {
        // These pin native detection policy independently of primary identity.
        // Configured newline splitting remains separate from regex validation.
        for language in [JstsLanguage::JavaScript, JstsLanguage::TypeScript] {
            for (header, regular_expression, source, expected) in [
                ("", false, "", 1),
                ("", false, "const value = 1;\n", 1),
                ("", false, "\nconst value = 1;\n", 0),
                ("", true, "const value = 1;\n", 0),
                ("// License\n", false, "// License\nconst value = 1;\n", 0),
                (
                    "// License\r\n// Extra",
                    false,
                    "// License\r\n// Extra\nconst value = 1;\n",
                    1,
                ),
                (
                    "// License\r// Extra",
                    false,
                    "// License\r// Extra\nconst value = 1;\n",
                    0,
                ),
                ("*", true, "const value = 1;\n", 0),
            ] {
                let rules = RuleOptions {
                    header_format: header.to_owned(),
                    header_is_regular_expression: regular_expression,
                    ..RuleOptions::default()
                };
                let findings = super::check_file_header(source, language, &rules);
                assert_eq!(findings.len(), expected, "{header:?} / {source:?}");
                for finding in findings {
                    assert_eq!(finding.message, "Add or update the header of this file.");
                    assert!(finding.fix.is_none());
                    assert!(finding.alternatives.is_empty());
                    assert!(finding.flows.is_empty());
                }
            }
        }
    }

    #[test]
    fn file_header_requires_configured_prefix() {
        let mut rules = RuleOptions {
            header_format: "// Copyright".to_string(),
            ..RuleOptions::default()
        };
        let missing = crate::analyze_with_rules(
            PathBuf::from("test.js"),
            "let x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(count_key(&report_keys(&missing), "javascript:S1451"), 1);

        let present = crate::analyze_with_rules(
            PathBuf::from("test.js"),
            "// Copyright\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(count_key(&report_keys(&present), "javascript:S1451"), 0);

        rules.header_is_regular_expression = true;
        rules.header_format = r"^// \(c\) \d{4}".to_string();
        let regex_present = crate::analyze_with_rules(
            PathBuf::from("test.js"),
            "// (c) 2026 ACME\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(
            count_key(&report_keys(&regex_present), "javascript:S1451"),
            0
        );

        let regex_missing = crate::analyze_with_rules(
            PathBuf::from("test.js"),
            "// Other header\nlet x = 1;\n",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
            &rules,
        );
        assert_eq!(
            count_key(&report_keys(&regex_missing), "javascript:S1451"),
            1
        );
    }
    #[test]
    fn file_header_empty_format_fires_on_nonempty_first_line() {
        let rules = RuleOptions::default();
        assert!(rules.header_format.is_empty());
        // `SonarJS` treats an empty `headerFormat` as one expected empty
        // line, so any file whose first line is non-empty is flagged.
        let findings = keys_with_rules("let a = 1;\n", &rules);
        assert_eq!(count_key(&findings, "javascript:S1451"), 1);
        let blank_first = keys_with_rules("\nlet a = 1;\n", &rules);
        assert_eq!(count_key(&blank_first, "javascript:S1451"), 0);
    }

    #[test]
    fn file_header_must_appear_at_the_very_start() {
        let rules = RuleOptions {
            header_format: "// License".to_string(),
            ..RuleOptions::default()
        };
        let late = keys_with_rules("let a = 1;\n// License\n", &rules);
        assert_eq!(count_key(&late, "javascript:S1451"), 1);
    }
}
