use crate::cst::issue;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;

/// csharpsquid:S104 — file exceeds `maximumFileLocThreshold` lines of code.
pub(crate) fn check(
    code_line_count: usize,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_file_loc_threshold).unwrap_or(usize::MAX);
    if code_line_count <= maximum {
        return Vec::new();
    }
    vec![issue(
        language,
        "S104",
        format!(
            "This file has {} lines, which is greater than {} authorized. Split it into smaller files.",
            code_line_count, options.maximum_file_loc_threshold
        ),
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    )]
}
