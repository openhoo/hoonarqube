use crate::CsLanguage;
use crate::cst::{issue, to_u32};
use hoonarqube_ir::Issue;

/// csharpsquid:S105 — no tab characters for indentation.
pub(crate) fn check(source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (index, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let Some(column) = leading_tab_column(line) else {
            continue;
        };
        let line_number = to_u32(index) + 1;
        issues.push(issue(
            language,
            "S105",
            "Replace all tab characters in this file by spaces.",
            hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: line_number,
                    column,
                },
                end: hoonarqube_ir::Pos {
                    line: line_number,
                    column: column + 1,
                },
            },
        ));
    }
    issues
}

/// Column of the first tab inside a line's leading whitespace run.
fn leading_tab_column(line: &str) -> Option<u32> {
    let mut column = 0;
    for character in line.chars() {
        match character {
            '\t' => return Some(column),
            ' ' => column += 1,
            _ => return None,
        }
    }
    None
}
