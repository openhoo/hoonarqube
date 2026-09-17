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
        check_percent_call(expr, index, source, &mut issues);
    }
    issues
}

/// Flags one `%` formatting call whose argument count or shape contradicts
/// the format string's conversions.
fn check_percent_call(expr: &Expr, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let Some((format_text, arguments, right_operand, _range)) = percent_format_parts(expr) else {
        return;
    };
    let Some(conversions) = percent_conversions(&format_text) else {
        return;
    };
    {
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
            return;
        }
        // The reference only verifies literal argument collections: a
        // non-literal right operand (name, call, ...) is unverifiable.
        if !matches!(
            right_operand,
            Expr::Tuple(_) | Expr::List(_) | Expr::Set(_) | Expr::Dict(_)
        ) {
            if conversions.len() > 1
                && matches!(
                    right_operand,
                    Expr::StringLiteral(_)
                        | Expr::BytesLiteral(_)
                        | Expr::NumberLiteral(_)
                        | Expr::BooleanLiteral(_)
                        | Expr::NoneLiteral(_)
                        | Expr::EllipsisLiteral(_)
                )
            {
                issues.push(issue_at(
                    "python:S2275",
                    "Replace this formatting argument with a tuple.",
                    right_operand.range(),
                    index,
                    source,
                ));
            }
            return;
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
}
