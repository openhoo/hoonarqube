// --- literal-kind helpers for the operator/exception family

use crate::support::literal_kind;
use crate::support::string_value_text;
use ruff_python_ast::Expr;

/// Kinds that support neither membership, item access, nor iteration.
const NON_SUPPORTING_KINDS: [&str; 2] = ["number", "boolean"];

pub(crate) fn is_non_supporting_kind(kind: &str) -> bool {
    NON_SUPPORTING_KINDS.contains(&kind)
}

/// Whether `raise <expr>` / `from <expr>` / `except <expr>` is a plain literal
/// that cannot behave like an exception (tuples excluded for legacy forms).
pub(crate) fn is_non_exception_literal(expr: &Expr) -> bool {
    literal_kind(expr).is_some_and(|kind| {
        matches!(
            kind,
            "number" | "string" | "bytes" | "boolean" | "list" | "set" | "dict"
        )
    })
}

pub(crate) fn is_arithmetic_op(op: ruff_python_ast::Operator) -> bool {
    matches!(
        op,
        ruff_python_ast::Operator::Add
            | ruff_python_ast::Operator::Sub
            | ruff_python_ast::Operator::Mult
            | ruff_python_ast::Operator::Div
            | ruff_python_ast::Operator::FloorDiv
            | ruff_python_ast::Operator::Mod
            | ruff_python_ast::Operator::Pow
            | ruff_python_ast::Operator::LShift
            | ruff_python_ast::Operator::RShift
            | ruff_python_ast::Operator::BitAnd
            | ruff_python_ast::Operator::BitOr
            | ruff_python_ast::Operator::BitXor
    )
}

/// Conservative invalidity table for arithmetic between two plain literals.
pub(crate) fn binop_literal_invalid(
    op: ruff_python_ast::Operator,
    left: &str,
    right: &str,
) -> bool {
    let sequence_like = |kind: &str| matches!(kind, "string" | "bytes" | "list" | "tuple");
    if left == "none"
        || right == "none"
        || left == "dict"
        || right == "dict"
        || left == "set"
        || right == "set"
    {
        return true;
    }
    if left == right && matches!(left, "string" | "bytes") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    if left == right && matches!(left, "list" | "tuple") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    let seq_num =
        sequence_like(left) && right == "number" || sequence_like(right) && left == "number";
    if seq_num {
        return !matches!(op, ruff_python_ast::Operator::Mult);
    }
    // Remaining cross-kind pairs (e.g. string with list) are always invalid.
    left != right
}

/// Whether `left <op> right` between two plain literals is definitely
/// invalid. `%` with a string or bytes literal on the left and a tuple on
/// the right is printf-style formatting (issue #113): valid whenever the
/// format conversions accept the tuple arguments.
pub(crate) fn binop_literals_invalid(
    op: ruff_python_ast::Operator,
    left: &Expr,
    right: &Expr,
    left_kind: &str,
    right_kind: &str,
) -> bool {
    if matches!(op, ruff_python_ast::Operator::Mod)
        && matches!(left_kind, "string" | "bytes")
        && right_kind == "tuple"
    {
        return printf_tuple_invalid(left, right);
    }
    binop_literal_invalid(op, left_kind, right_kind)
}

/// One parsed `%` conversion of an old-style format literal.
struct FormatConversion {
    star_arguments: usize,
    conversion: char,
}

/// Whether the tuple argument of `format % tuple` definitely fails at
/// runtime: malformed format, mapping-key conversions (they require a
/// mapping, never a tuple), an argument-count mismatch, or an element type
/// the conversion rejects.
fn printf_tuple_invalid(format: &Expr, argument: &Expr) -> bool {
    let Expr::Tuple(tuple) = argument else {
        return true;
    };
    let (format_text, bytes_format) = match format {
        Expr::StringLiteral(literal) => (string_value_text(&literal.value), false),
        Expr::BytesLiteral(literal) => {
            let mut bytes = Vec::new();
            for part in literal.value.as_slice() {
                bytes.extend_from_slice(&part.value);
            }
            (String::from_utf8_lossy(&bytes).into_owned(), true)
        }
        _ => return true,
    };
    let Some(conversions) = format_conversions(&format_text, bytes_format) else {
        return true;
    };
    let stars: usize = conversions
        .iter()
        .map(|conversion| conversion.star_arguments)
        .sum();
    if conversions.len() + stars != tuple.elts.len() {
        return true;
    }
    let mut next = 0;
    for conversion in &conversions {
        for _ in 0..conversion.star_arguments {
            if !is_int_literal(&tuple.elts[next]) {
                return true;
            }
            next += 1;
        }
        if !conversion_accepts(conversion.conversion, &tuple.elts[next], bytes_format) {
            return true;
        }
        next += 1;
    }
    false
}

/// Parsed `%` conversions of an old-style format literal; `None` when the
/// literal is malformed or uses mapping keys.
fn format_conversions(format: &str, bytes_format: bool) -> Option<Vec<FormatConversion>> {
    let chars: Vec<char> = format.chars().collect();
    let mut conversions = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '%' {
            index += 1;
            continue;
        }
        index += 1;
        if chars.get(index) == Some(&'%') {
            index += 1;
            continue;
        }
        if chars.get(index) == Some(&'(') {
            return None;
        }
        let (conversion, next) = parse_conversion(&chars, index, bytes_format)?;
        conversions.push(conversion);
        index = next;
    }
    Some(conversions)
}

/// Parses one `%` conversion: flags, width, precision, C length modifiers,
/// and the conversion character. `index` sits after `%`.
fn parse_conversion(
    chars: &[char],
    mut index: usize,
    bytes_format: bool,
) -> Option<(FormatConversion, usize)> {
    let mut star_arguments = 0;
    index = skip_format_field(chars, index, &mut star_arguments);
    if chars.get(index) == Some(&'.') {
        index = skip_format_field(chars, index + 1, &mut star_arguments);
    }
    while matches!(chars.get(index), Some('h' | 'l' | 'L')) {
        index += 1;
    }
    let conversion = *chars.get(index)?;
    let supported = matches!(
        conversion,
        'd' | 'i'
            | 'u'
            | 'o'
            | 'x'
            | 'X'
            | 'e'
            | 'E'
            | 'f'
            | 'F'
            | 'g'
            | 'G'
            | 'c'
            | 'r'
            | 's'
            | 'a'
            | 'b'
    ) && (bytes_format || conversion != 'b');
    if !supported {
        return None;
    }
    Some((
        FormatConversion {
            star_arguments,
            conversion,
        },
        index + 1,
    ))
}

/// Skips a width or precision field; `*` consumes one int argument.
fn skip_format_field(chars: &[char], mut index: usize, star_arguments: &mut usize) -> usize {
    if chars.get(index) == Some(&'*') {
        *star_arguments += 1;
        return index + 1;
    }
    while chars.get(index).is_some_and(char::is_ascii_digit) {
        index += 1;
    }
    index
}

/// Whether a `%` conversion accepts a literal tuple element; elements that
/// are not plain literals cannot be proven incompatible and are accepted.
fn conversion_accepts(conversion: char, element: &Expr, bytes_format: bool) -> bool {
    let Some(kind) = literal_kind(element) else {
        return true;
    };
    match conversion {
        's' | 'b' => !bytes_format || kind == "bytes",
        'r' | 'a' => true,
        'c' => char_conversion_accepts(element, kind),
        _ => is_real_number_literal(element),
    }
}

/// `%c` accepts an int-like value or a single-character string/bytes literal.
fn char_conversion_accepts(element: &Expr, kind: &str) -> bool {
    match (element, kind) {
        (_, "boolean") => true,
        (Expr::NumberLiteral(_), "number") => is_int_literal(element),
        (Expr::StringLiteral(literal), "string") => {
            literal
                .value
                .iter()
                .map(|part| part.value.chars().count())
                .sum::<usize>()
                == 1
        }
        (Expr::BytesLiteral(literal), "bytes") => {
            literal
                .value
                .as_slice()
                .iter()
                .map(|part| part.value.len())
                .sum::<usize>()
                == 1
        }
        _ => false,
    }
}

/// Whether a literal is a plain integer (`%*` width/precision arguments).
fn is_int_literal(element: &Expr) -> bool {
    matches!(
        element,
        Expr::NumberLiteral(number) if matches!(number.value, ruff_python_ast::Number::Int(_))
    ) || matches!(element, Expr::BooleanLiteral(_))
}

/// Whether a literal is a real number; the numeric conversions accept ints
/// and floats (booleans are ints), while complex and non-numbers raise.
fn is_real_number_literal(element: &Expr) -> bool {
    match element {
        Expr::NumberLiteral(number) => {
            !matches!(number.value, ruff_python_ast::Number::Complex { .. })
        }
        Expr::BooleanLiteral(_) => true,
        _ => false,
    }
}
