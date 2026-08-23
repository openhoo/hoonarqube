use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::percent_conversions;
use crate::support::percent_format_parts;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_percent_argument_counts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Some((format_text, arguments, right_operand, range)) = percent_format_parts(expr)
        else {
            return;
        };
        let Some(conversions) = percent_conversions(&format_text) else {
            return;
        };
        if matches!(right_operand, Expr::Dict(_)) {
            if !conversions.is_empty() && !format_text.contains("%(") {
                issues.push(issue_at(
                    "python:S2275",
                    "Add mapping keys to this format string; a mapping is formatted without them.",
                    range,
                    index,
                    source,
                ));
            }
            return;
        }
        if conversions.len() != arguments.len() {
            issues.push(issue_at(
                "python:S2275",
                "Fix this format string; its conversions do not match the provided arguments.",
                range,
                index,
                source,
            ));
        }
    });
    issues
}
