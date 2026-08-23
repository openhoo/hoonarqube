// Rule module s1451_file_header (generated).

use hoonarqube_ir::{Issue};
use crate::{JstsLanguage};
use crate::context::{AnalysisContext, RuleOptions};
use crate::engine::pattern_parser::{regex_prefix_match};


pub(crate) fn check_file_header(source: &str, language: JstsLanguage, rules: &RuleOptions) -> Vec<Issue> {
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
