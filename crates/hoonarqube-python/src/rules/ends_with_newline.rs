use crate::support::to_u32;
use hoonarqube_ir::Issue;

/// python:S113 — file must end with a newline character; empty files exempt.
pub(crate) fn check_ends_with_newline(source: &str) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let last_line = to_u32(source.split_inclusive('\n').count());
    let length = source.split_inclusive('\n').next_back().map_or(0, |chunk| {
        to_u32(chunk.trim_end_matches('\r').chars().count())
    });
    vec![Issue {
        rule_key: "python:S113".to_string(),
        message: "Add a newline character at the end of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line: last_line,
                column: 0,
            },
            end: hoonarqube_ir::Pos {
                line: last_line,
                column: length,
            },
        },
    }]
}
