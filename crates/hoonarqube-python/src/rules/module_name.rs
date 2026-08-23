use crate::support::module_name_matches_convention;
use crate::support::to_pos;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextSize;

/// python:S1578 — module file stem must match
/// `(([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+))`.
pub(crate) fn check_module_name(
    path: &std::path::Path,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Vec::new();
    };
    if module_name_matches_convention(stem) {
        return Vec::new();
    }
    vec![Issue {
        rule_key: "python:S1578".to_string(),
        message: "Rename this module to comply with the naming convention.".to_string(),
        range: hoonarqube_ir::Range {
            start: to_pos(TextSize::from(0), index, source),
            end: to_pos(TextSize::from(0), index, source),
        },
    }]
}
