use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::percent_conversions;
use crate::support::percent_format_parts;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_percent_argument_counts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Some((format_text, arguments, right_operand, _range)) = percent_format_parts(expr)
        else {
            continue;
        };
        let Some(conversions) = percent_conversions(&format_text) else {
            continue;
        };
        if matches!(right_operand, Expr::Dict(_)) {
            if conversions.len() == 1
                && matches!(
                    conversions[0],
                    b'd' | b'i'
                        | b'u'
                        | b'x'
                        | b'X'
                        | b'o'
                        | b'e'
                        | b'E'
                        | b'f'
                        | b'F'
                        | b'g'
                        | b'G'
                )
                && !format_text.contains("%(")
            {
                issues.push(issue_at(
                    "python:S2275",
                    &format!(
                        "Replace this value with a number as \"%{}\" requires.",
                        char::from(conversions[0])
                    ),
                    right_operand.range(),
                    index,
                    source,
                ));
            }
            continue;
        }
        if conversions.len() != arguments.len() {
            let message = if conversions.len() > arguments.len() {
                format!(
                    "Add {} missing argument(s).",
                    conversions.len() - arguments.len()
                )
            } else {
                format!(
                    "Remove {} extra argument(s).",
                    arguments.len() - conversions.len()
                )
            };
            issues.push(issue_at(
                "python:S2275",
                &message,
                right_operand.range(),
                index,
                source,
            ));
        }
    }
    issues
}
