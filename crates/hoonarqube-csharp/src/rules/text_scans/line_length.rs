use crate::cst::to_u32;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
pub(crate) fn check(source: &str, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
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
                    "Split this {length} characters long line (which is greater than {} authorized).",
                    options.maximum_line_length,
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
                fix: None,
            });
        }
    }
    issues
}
