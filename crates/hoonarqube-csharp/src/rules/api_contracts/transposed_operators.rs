use crate::CsLanguage;
use crate::cst::{issue, to_u32};
use hoonarqube_ir::Issue;

/// csharpsquid:S2757 — `= +` is two operators where one was meant.
pub(crate) fn check(source: &str, language: CsLanguage) -> Vec<Issue> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| has_transposed_assignment(line))
        .map(|(index, line)| {
            issue(
                language,
                "S2757",
                "Fix this mistyped assignment operator.",
                hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: to_u32(line.chars().count()),
                    },
                },
            )
        })
        .collect()
}

/// Whether the line carries the transposed `= +` operator pair outside a
/// comment.
fn has_transposed_assignment(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }
    let bytes = line.as_bytes();
    for index in 1..bytes.len().saturating_sub(1) {
        if bytes[index] != b'=' || bytes.get(index + 1) != Some(&b'+') {
            continue;
        }
        let before = bytes[index - 1];
        let not_other_operator = !matches!(
            before,
            b'=' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'!' | b'|' | b'&' | b'^'
        );
        if not_other_operator {
            return true;
        }
    }
    false
}
