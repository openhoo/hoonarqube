// --- python:S2275 / python:S3457 — printf-style formatting

use crate::support::string_value_text;
use ruff_python_ast::Expr;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

/// Conversion characters of a printf-style format string; `None` marks an
/// invalid or truncated specification.
pub(crate) fn percent_conversions(format_text: &str) -> Option<Vec<u8>> {
    let bytes = format_text.as_bytes();
    let mut conversions = Vec::new();
    let mut position = 0;
    while let Some(relative) = bytes[position..].iter().position(|byte| *byte == b'%') {
        position += relative + 1;
        let (conversion, next) = parse_percent_conversion(bytes, position)?;
        if let Some(conversion) = conversion {
            conversions.push(conversion);
        }
        position = next;
    }
    Some(conversions)
}

/// Parses one conversion after its leading `%`. Escaped `%%` returns no
/// conversion character; malformed and truncated specifications fail closed.
fn parse_percent_conversion(bytes: &[u8], mut position: usize) -> Option<(Option<u8>, usize)> {
    if *bytes.get(position)? == b'%' {
        return Some((None, position + 1));
    }
    skip_bytes(bytes, &mut position, |byte| {
        matches!(byte, b'-' | b'+' | b' ' | b'#' | b'0')
    });
    skip_bytes(bytes, &mut position, |byte| byte.is_ascii_digit());
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        skip_bytes(bytes, &mut position, |byte| byte.is_ascii_digit());
    }
    skip_bytes(bytes, &mut position, |byte| {
        matches!(byte, b'h' | b'l' | b'L')
    });
    let conversion = *bytes.get(position)?;
    b"diouxXeEfFgGcrsa"
        .contains(&conversion)
        .then_some((Some(conversion), position + 1))
}

fn skip_bytes(bytes: &[u8], position: &mut usize, predicate: impl Fn(u8) -> bool) {
    while bytes.get(*position).copied().is_some_and(&predicate) {
        *position += 1;
    }
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

#[cfg(test)]
mod tests {
    use super::percent_conversions;

    #[test]
    fn percent_parser_handles_escapes_flags_width_precision_and_lengths() {
        assert_eq!(
            percent_conversions("%% %-05d %12.3f %lld %s"),
            Some(vec![b'd', b'f', b'd', b's'])
        );
    }

    #[test]
    fn percent_parser_rejects_truncated_and_unknown_specifiers() {
        assert_eq!(percent_conversions("value %"), None);
        assert_eq!(percent_conversions("value %q"), None);
    }
}
