use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

pub(crate) fn check_percent_argument_counts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Some((format_text, arguments, right_operand, range)) = percent_format_parts(expr)
        else {
            continue;
        };
        let Some(conversions) = percent_conversions(&format_text) else {
            continue;
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
            continue;
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
    }
    issues
}

// --- python:S2275 / python:S3457 — printf-style formatting ---------------------

/// Conversion characters of a printf-style format string; `None` marks an
/// invalid or truncated specification.
pub(crate) fn percent_conversions(format_text: &str) -> Option<Vec<u8>> {
    let bytes = format_text.as_bytes();
    let mut conversions = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] != b'%' {
            position += 1;
            continue;
        }
        position += 1;
        if position >= bytes.len() {
            return None;
        }
        if bytes[position] == b'%' {
            position += 1;
            continue;
        }
        while position < bytes.len() && matches!(bytes[position], b'-' | b'+' | b' ' | b'#' | b'0')
        {
            position += 1;
        }
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            position += 1;
        }
        if position < bytes.len() && bytes[position] == b'.' {
            position += 1;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
        }
        while position < bytes.len() && matches!(bytes[position], b'h' | b'l' | b'L') {
            position += 1;
        }
        let conversion = *bytes.get(position)?;
        if b"diouxXeEfFgGcrsa".contains(&conversion) {
            conversions.push(conversion);
        } else {
            return None;
        }
        position += 1;
    }
    Some(conversions)
}

/// `(format text, arguments, right operand, span)` of a `%`-formatted string
/// literal; `None` for anything else.
pub(crate) fn percent_format_parts(expr: &Expr) -> Option<(String, Vec<&Expr>, &Expr, TextRange)> {
    let Expr::BinOp(bin_op) = expr else {
        return None;
    };
    if !matches!(bin_op.op, ruff_python_ast::Operator::Mod) {
        return None;
    }
    let Expr::StringLiteral(literal) = bin_op.left.as_ref() else {
        return None;
    };
    let arguments: Vec<&Expr> = match bin_op.right.as_ref() {
        Expr::Tuple(tuple) => tuple.elts.iter().collect(),
        other => vec![other],
    };
    Some((
        string_value_text(&literal.value),
        arguments,
        bin_op.right.as_ref(),
        bin_op.range(),
    ))
}
