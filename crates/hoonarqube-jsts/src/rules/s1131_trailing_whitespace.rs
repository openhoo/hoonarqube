// Rule module s1131_trailing_whitespace (generated).

use hoonarqube_ir::{Issue};
use crate::{JstsLanguage};
use crate::context::{AnalysisContext};
use crate::support::{to_u32};


pub(crate) fn check_trailing_whitespace(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S1131", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches('\n');
        let content = line.strip_suffix('\r').unwrap_or(line);
        let trailing = content.len() - content.trim_end_matches([' ', '\t']).len();
        if trailing == 0 || content.is_empty() {
            continue;
        }
        let line_number = to_u32(zero_based) + 1;
        let start_column = to_u32(content.len() - trailing);
        issues.push(Issue {
            rule_key: rule_key.clone(),
            message: "Remove all trailing whitespaces.".to_string(),
            range: hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: line_number,
                    column: start_column,
                },
                end: hoonarqube_ir::Pos {
                    line: line_number,
                    column: to_u32(content.len()),
                },
            },
        });
    }
    issues
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_trailing_whitespace(ctx.source, ctx.language)
}
