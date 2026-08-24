// Rule module s104_lines_of_code (generated).

use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::Statement;
use oxc_span::GetSpan;
use std::collections::BTreeSet;

pub(crate) fn check_too_many_lines_of_code(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    // Same notion of code lines as `file_metrics`: statement coverage
    // excludes blank lines and pure-comment lines.
    let code_lines: BTreeSet<u32> = body
        .iter()
        .flat_map(|statement| index.covered_lines(statement.span()))
        .collect();
    let count = code_lines.len();
    let maximum = usize::try_from(rules.maximum_lines_of_code).unwrap_or(usize::MAX);
    if count <= maximum {
        return Vec::new();
    }
    vec![Issue {
        rule_key: format!("{}:S104", language.prefix()),
        message: format!(
            "This file has {} lines of code, which is greater than {} authorized. \
             Split it into smaller pieces.",
            count, rules.maximum_lines_of_code
        ),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_too_many_lines_of_code(
        ctx.program.body.as_slice(),
        ctx.index,
        ctx.language,
        ctx.rules,
    )
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn lines_of_code_counts_statements_not_blank_or_comment_lines() {
        let rules = RuleOptions {
            maximum_lines_of_code: 2,
            ..RuleOptions::default()
        };
        // Four physical lines, but only two code lines: within the threshold.
        let within = keys_with_rules("let a = 1;\n\n// filler\nlet b = 2;\n", &rules);
        assert_eq!(count_key(&within, "javascript:S104"), 0);

        // Blank and comment lines still do not count toward three statements.
        let over = keys_with_rules(
            "let a = 1;\n\n// filler\nlet b = 2;\n\n// filler\nlet c = 3;\n",
            &rules,
        );
        assert_eq!(count_key(&over, "javascript:S104"), 1);
    }
}
