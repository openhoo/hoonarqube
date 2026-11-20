use crate::AnalyzerOptions;
use hoonarqube_ir::Issue;
use std::path::Path;

// ---------------------------------------------------------------------------
// Tier A — size metrics (python:S104, python:S107, python:S1142,
// python:S138, python:S134).
// ---------------------------------------------------------------------------

/// python:S104 — physical file lines against `maximumLinesOfCode`.
///
/// Despite the parameter name, the reference counts comments, blank rows,
/// docstrings, and the empty terminal row in the same way as file metrics.
pub(crate) fn check_lines_of_code(
    path: &Path,
    metrics: &hoonarqube_ir::FileMetrics,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    if metrics.lines <= options.maximum_lines_of_code {
        return Vec::new();
    }
    let name = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    vec![Issue::new(
        "python:S104",
        format!(
            "File \"{name}\" has {} lines, which is greater than {} authorized. Split it into smaller files.",
            grouped_count(metrics.lines),
            grouped_count(options.maximum_lines_of_code),
        ),
        hoonarqube_ir::Range::file_level(),
    )]
}

fn grouped_count(value: u32) -> String {
    if value < 1000 {
        value.to_string()
    } else {
        format!("{},{:03}", grouped_count(value / 1000), value % 1000)
    }
}
