use crate::cst::{issue, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;

/// csharpsquid:S1451 — required file header. An empty `header_format`
/// disables the check; regular-expression headers are not evaluated because
/// this analyzer carries no regex engine.
pub(crate) fn check(source: &str, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    if options.header_format.is_empty() || options.header_is_regular_expression {
        return Vec::new();
    }
    let without_trailing_newline = options
        .header_format
        .strip_suffix('\n')
        .unwrap_or(&options.header_format);
    if source.starts_with(options.header_format.as_str())
        || source.starts_with(without_trailing_newline)
    {
        return Vec::new();
    }
    let column = to_u32(
        source
            .split('\n')
            .next()
            .map_or(0, |first_line| first_line.chars().count()),
    );
    vec![issue(
        language,
        "S1451",
        "Add or update the required header of this file.",
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column },
        },
    )]
}
