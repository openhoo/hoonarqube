// Rule module s103_line_length (generated).

use hoonarqube_ir::{Issue};
use crate::{AnalyzerOptions, JstsLanguage};
use crate::context::{AnalysisContext};
use crate::support::{to_u32};


pub(crate) fn check_line_length(
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let rule_key = format!("{}:S103", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: format!(
                    "This line exceeds the maximum allowed length of {} characters.",
                    options.maximum_line_length
                ),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: to_u32(length),
                    },
                },
            });
        }
    }
    issues
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_line_length(ctx.source, ctx.language, ctx.options)
}
