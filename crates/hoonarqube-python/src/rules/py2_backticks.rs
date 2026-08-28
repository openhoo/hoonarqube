use crate::support::to_range;
use crate::support::to_u32;
use crate::support::unmasked_segments;
use hoonarqube_ir::{Issue, TextEdit};
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

// ---------------------------------------------------------------------------
// Python 2 relics and token-level operator confusion.
// ---------------------------------------------------------------------------

/// python:BackticksUsage — backtick `repr()` quoting.
pub(crate) fn check_py2_backticks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut backticks = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (offset, ch) in segment.char_indices() {
            if ch == '`' {
                backticks.push(base + offset);
            }
        }
    }
    backticks
        .chunks_exact(2)
        .map(|pair| {
            let open = TextSize::from(to_u32(pair[0]));
            let close = TextSize::from(to_u32(pair[1]));
            Issue::new(
                "python:BackticksUsage",
                "Use \"repr\" instead.",
                to_range(
                    TextRange::new(open, close + TextSize::new(1)),
                    index,
                    source,
                ),
            )
            .with_fix(
                "Replace backtick with \"repr()\".",
                vec![
                    TextEdit {
                        range: to_range(
                            TextRange::new(open, open + TextSize::new(1)),
                            index,
                            source,
                        ),
                        replacement: "repr(".to_string(),
                    },
                    TextEdit {
                        range: to_range(
                            TextRange::new(close, close + TextSize::new(1)),
                            index,
                            source,
                        ),
                        replacement: ")".to_string(),
                    },
                ],
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn backticks_report_whole_expression_with_exact_message() {
        let report = scan("value = `num`\n");
        let issues = findings(&report, "python:BackticksUsage");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].message, "Use \"repr\" instead.");
        assert_eq!(issues[0].range.start.line, 1);
        assert_eq!(issues[0].range.start.column, 8);
        assert_eq!(issues[0].range.end.line, 1);
        assert_eq!(issues[0].range.end.column, 13);
    }

    #[test]
    fn backtick_quick_fix_matches_sonar_replacement() {
        let source = "value = `num`\n";
        let report = scan(source);
        let issue = findings(&report, "python:BackticksUsage")[0];
        let fix = issue.fix.as_ref().expect("quick fix attached");
        assert_eq!(fix.message, "Replace backtick with \"repr()\".");
        let edits = fix.edits.iter().collect::<Vec<_>>();
        let fixed = hoonarqube_ir::apply_fixes(source, &edits).expect("fix applies");
        assert_eq!(fixed, "value = repr(num)\n");
    }

    #[test]
    fn multiline_and_multiple_backtick_pairs_stay_distinct() {
        let report = scan("a = `1\n + 2`\nb = `x`\n");
        let issues = findings(&report, "python:BackticksUsage");
        assert_eq!(issues.len(), 2);
        assert_eq!(
            (issues[0].range.start.line, issues[0].range.end.line),
            (1, 2)
        );
        assert_eq!(
            (issues[1].range.start.line, issues[1].range.end.line),
            (3, 3)
        );
    }

    #[test]
    fn comments_strings_and_unmatched_backticks_do_not_form_findings() {
        let report = scan("text = '`'\n# `comment`\nvalue = `broken\n");
        assert!(findings(&report, "python:BackticksUsage").is_empty());
    }
}
