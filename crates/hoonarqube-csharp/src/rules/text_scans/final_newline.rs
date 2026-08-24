use crate::CsLanguage;
use crate::cst::{issue, to_u32};
use hoonarqube_ir::Issue;

/// csharpsquid:S113 — files must end with a newline.
pub(crate) fn check(source: &str, language: CsLanguage) -> Vec<Issue> {
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
    vec![issue(
        language,
        "S113",
        "Add a new line at the end of this file.",
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line, column },
            end: hoonarqube_ir::Pos { line, column },
        },
    )]
}
