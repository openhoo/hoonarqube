use crate::CsLanguage;
use crate::cst::{issue, to_u32};
use hoonarqube_ir::Issue;
use std::path::Path;

/// csharpsquid:S113 — files must end with a newline.
pub(crate) fn check(path: &Path, source: &str, language: CsLanguage) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let line = to_u32(source.split_inclusive('\n').count());
    let column = to_u32(
        source
            .rsplit('\n')
            .next()
            .map_or(0, |chunk| chunk.chars().count()),
    );
    let file_name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    vec![issue(
        language,
        "S113",
        format!("Add a new line at the end of the file '{file_name}'."),
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line,
                column: column.saturating_sub(1),
            },
            end: hoonarqube_ir::Pos { line, column },
        },
    )]
}
