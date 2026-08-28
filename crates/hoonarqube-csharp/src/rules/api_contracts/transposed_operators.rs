use crate::CsLanguage;
use crate::cst::{issue, to_u32};
use hoonarqube_ir::Issue;

/// csharpsquid:S2757 — `= +` is two operators where one was meant.
pub(crate) fn check(source: &str, language: CsLanguage) -> Vec<Issue> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| has_transposed_assignment(line).map(|column| (index, column)))
        .map(|(index, column)| {
            issue(
                language,
                "S2757",
                "Was '+=' meant instead?",
                hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: to_u32(column),
                    },
                    end: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: to_u32(column) + 1,
                    },
                },
            )
        })
        .collect()
}

/// Whether the line carries the transposed `= +` operator pair outside a
/// comment.
fn has_transposed_assignment(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return None;
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
            return Some(line[..=index].chars().count());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2757_flags_each_transposed_line_and_counts_them() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        total =+ amount;\n        count =+ step;\n        Log(total);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2757");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2757_ignores_spaced_unary_plus_and_operator_pairs() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        total = +amount;\n        if (a ==+ b) { }\n        delta =- step;\n        /* note */ skipped =+ 1;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2757").is_empty());
    }
}
