use crate::AnalyzerOptions;
use hoonarqube_ir::Issue;

// ---------------------------------------------------------------------------
// Tier A — size metrics (python:S104, python:S107, python:S1142,
// python:S138, python:S134).
// ---------------------------------------------------------------------------

/// python:S104 — total lines of code against `maximumLinesOfCode`.
pub(crate) fn check_lines_of_code(
    metrics: &hoonarqube_ir::FileMetrics,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    if metrics.code_lines <= options.maximum_lines_of_code {
        return Vec::new();
    }
    vec![Issue {
        rule_key: "python:S104".to_string(),
        message: format!(
            "This file has {} lines of code, which is greater than the {} authorized.",
            metrics.code_lines, options.maximum_lines_of_code
        ),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}
