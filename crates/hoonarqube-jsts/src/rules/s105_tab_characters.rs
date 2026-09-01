// Rule module s105_tab_characters (generated).

use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::to_u32;
use hoonarqube_ir::Issue;

fn check_tab_characters(source: &str, language: JstsLanguage) -> Vec<Issue> {
    let rule_key = format!("{}:S105", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line_number = to_u32(zero_based) + 1;
        if chunk.contains('\t') {
            let line = chunk.strip_suffix('\n').unwrap_or(chunk);
            let line = line.strip_suffix('\r').unwrap_or(line);
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: "Replace all tab characters in this file by sequences of white-spaces."
                    .to_string(),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: to_u32(line.chars().count()),
                    },
                },
                fix: None,
                flows: Vec::new(),
            });
        }
    }
    issues
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_tab_characters(ctx.source, ctx.language)
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn tab_characters_flag_each_tabbed_line_at_first_tab_column() {
        let report = js("\tlet a = 1;\nlet b = 2;\n\t\tlet c = 3;\n");
        let tabs: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S105")
            .collect();
        assert_eq!(tabs.len(), 2);
        assert_eq!(tabs[0].range.start.line, 1);
        assert_eq!(tabs[0].range.start.column, 0);
        assert_eq!(tabs[1].range.start.line, 3);
        assert_eq!(tabs[1].range.start.column, 0);

        let spaced = js_keys("let a = 1;\nlet b = 2;\n");
        assert_eq!(count_key(&spaced, "javascript:S105"), 0);
    }

    #[test]
    fn tab_character_issue_has_precise_span() {
        let report = js("greet();\n\treset();\n");
        assert_eq!(
            report.issues,
            vec![issue(
                "javascript:S105",
                "Replace all tab characters in this file by sequences of white-spaces.",
                (2, 0),
                (2, 9),
            )]
        );
    }
}
