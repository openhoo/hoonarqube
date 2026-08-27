use crate::rules::nested_bodies::check_nested_bodies;
use crate::support::to_pos;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_suite(
    suite: &[ruff_python_ast::Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let line_of = |stmt: &ruff_python_ast::Stmt| to_pos(stmt.range().start(), index, source).line;

    let mut start = 0;
    while start < suite.len() {
        let first_line = line_of(&suite[start]);
        let mut end = start + 1;
        while end < suite.len() && line_of(&suite[end]) == first_line {
            end += 1;
        }
        for stmt in &suite[start + 1..end] {
            issues.push(Issue {
                rule_key: "python:OneStatementPerLine".to_string(),
                message: "Only one statement per line is allowed.".to_string(),
                range: to_range(stmt.range(), index, source),
                fix: None,
            });
        }
        for stmt in &suite[start..end] {
            check_nested_bodies(stmt, issues, index, source);
        }
        start = end;
    }
}
