// Rule module s105_tab_characters (generated).

use hoonarqube_ir::{Issue};
use crate::{JstsLanguage};
use crate::context::{AnalysisContext};
use crate::support::{to_u32};


pub(crate) fn check_tab_characters(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S105", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line_number = to_u32(zero_based) + 1;
        let column = chunk.find('\t');
        if let Some(column) = column {
            let column = to_u32(column);
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: "Replace all tab characters in this file by sequences of spaces."
                    .to_string(),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: column + 1,
                    },
                },
            });
        }
    }
    issues
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tab_characters(ctx.source, ctx.language)
}
