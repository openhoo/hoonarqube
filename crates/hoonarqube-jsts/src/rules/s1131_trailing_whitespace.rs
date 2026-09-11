// Rule module s1131_trailing_whitespace (generated).

use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{LineIndex, to_u32};
use hoonarqube_ir::Issue;

fn check_trailing_whitespace(index: &LineIndex, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S1131", language.prefix());
    let mut issues = Vec::new();
    for (line_number, content) in index.lines() {
        let trailing = content.len() - content.trim_end_matches([' ', '\t']).len();
        if trailing == 0 || content.is_empty() {
            continue;
        }
        let end_column = to_u32(content.chars().count());
        let start_column = end_column.saturating_sub(to_u32(trailing));
        issues.push(Issue {
            rule_key: rule_key.clone(),
            message: "Trailing spaces not allowed.".to_string(),
            range: hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: line_number,
                    column: start_column,
                },
                end: hoonarqube_ir::Pos {
                    line: line_number,
                    column: end_column,
                },
            },
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    }
    issues
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_trailing_whitespace(ctx.index, ctx.language)
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn trailing_whitespace_span_covers_only_padding() {
        let report = js("render(chart);   \n");
        assert_eq!(
            report.issues,
            vec![issue(
                "javascript:S1131",
                "Trailing spaces not allowed.",
                (1, 14),
                (1, 17),
            )]
        );
    }

    #[test]
    fn trailing_whitespace_columns_count_unicode_characters() {
        let report = js("const café = 1;  \n");
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S1131")
            .expect("trailing whitespace finding");
        assert_eq!(issue.range.start.column, 15);
        assert_eq!(issue.range.end.column, 17);
    }

    #[test]
    fn crlf_trailing_whitespace_strips_carriage_return() {
        let findings = js_keys("let b = 2; \r\n");
        assert_eq!(count_key(&findings, "javascript:S1131"), 1);
    }

    #[test]
    fn trailing_whitespace_uses_all_ecmascript_line_terminators() {
        let source =
            "let a = 1;  \rlet b = 2; \r\nlet c = 3;\u{2028}let d = 4;\t\u{2029}let e = 5;";
        let report = js(source);
        let spans: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S1131")
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.column,
                )
            })
            .collect();
        assert_eq!(spans, vec![(1, 10, 12), (2, 10, 11), (4, 10, 11)]);

        let clean =
            js_keys("let a = 1;\rlet b = 2;\r\nlet c = 3;\u{2028}let d = 4;\u{2029}let e = 5;");
        assert_eq!(count_key(&clean, "javascript:S1131"), 0);
    }

    #[test]
    fn clean_and_blank_lines_are_allowed() {
        let findings = js_keys("let a = 1;\n\nlet b = 2;\n");
        assert_eq!(count_key(&findings, "javascript:S1131"), 0);
    }
}
