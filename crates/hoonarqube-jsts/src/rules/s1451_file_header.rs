// Rule module s1451_file_header (generated).

use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::regex_prefix_match;
use hoonarqube_ir::Issue;

fn check_file_header(source: &str, language: JstsLanguage, rules: &RuleOptions) -> Vec<Issue> {
    // An empty `headerFormat` disables the rule, mirroring the catalog's
    // null default.
    if rules.header_format.is_empty() {
        return Vec::new();
    }
    let header_present = if rules.header_is_regular_expression {
        regex_prefix_match(&rules.header_format, source)
    } else {
        source.starts_with(rules.header_format.as_str())
    };
    if header_present {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S1451", language.prefix()),
        message: "Add or update the header of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_file_header(ctx.source, ctx.language, ctx.rules)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn file_header_requires_configured_prefix() {
        let mut rules = RuleOptions {
            header_format: "// Copyright\n".to_string(),
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
    fn file_header_rule_disabled_without_configured_format() {
        let rules = RuleOptions::default();
        assert!(rules.header_format.is_empty());
        let findings = keys_with_rules("let a = 1;\n", &rules);
        assert_eq!(count_key(&findings, "javascript:S1451"), 0);
    }

    #[test]
    fn file_header_must_appear_at_the_very_start() {
        let rules = RuleOptions {
            header_format: "// License\n".to_string(),
            ..RuleOptions::default()
        };
        let late = keys_with_rules("let a = 1;\n// License\n", &rules);
        assert_eq!(count_key(&late, "javascript:S1451"), 1);
    }
}
