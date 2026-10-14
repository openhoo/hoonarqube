// Rule module s1451_file_header (generated).

use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::regex_prefix_match;
use hoonarqube_ir::Issue;

fn check_file_header(source: &str, language: JstsLanguage, rules: &RuleOptions) -> Vec<Issue> {
    let header_present = if rules.header_is_regular_expression {
        // An empty `headerFormat` disables the file-header check.
        if rules.header_format.is_empty() {
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
        // Configured newline splitting and invalid regex handling are separate repairs.
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
                ("*", true, "const value = 1;\n", 1),
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
