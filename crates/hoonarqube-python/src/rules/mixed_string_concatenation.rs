use crate::support::{child_exprs, for_each_stmt, for_each_stmt_expr, issue_at, stmt_exprs};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Operator};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

const MAX_VISIBLE_SPLIT_COLUMN: usize = 65;

/// python:S5799 — implicit concatenation of same-style string or bytes parts.
///
/// Ruff represents adjacent text literals as one `ExprStringLiteral` or
/// `ExprBytesLiteral` with multiple parts. Looking at those parsed parts avoids
/// flagging unrelated literals in neighboring expressions and gives the
/// quick-fix pass the exact token ranges it needs. Prefix and quote mismatches
/// are deliberately ignored: the pinned `SonarPython` rule only reports a
/// concatenation for equal prefix/quote style.
pub(crate) fn check_mixed_string_concatenation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let (literal_range, parts): (TextRange, Vec<TextRange>) = match expr {
            Expr::StringLiteral(literal) => (
                literal.range(),
                literal.value.iter().map(Ranged::range).collect(),
            ),
            Expr::BytesLiteral(literal) => (
                literal.range(),
                literal.value.iter().map(Ranged::range).collect(),
            ),
            _ => return,
        };
        for pair in parts.windows(2) {
            let previous = pair[0];
            let current = pair[1];
            if !same_prefix_and_quotes(source, previous, current) {
                continue;
            }
            let same_line =
                line_number(source, previous.start()) == line_number(source, current.start());
            let (collection, blocked) = string_context(parsed, literal_range);
            if blocked
                || (!same_line
                    && (!collection || visible_split_exception(source, previous, current)))
            {
                continue;
            }
            let message = if same_line {
                "Merge these implicitly concatenated strings; or did you forget a comma?"
            } else {
                "Add a \"+\" operator to make the string concatenation explicit; or did you forget a comma?"
            };
            issues.push(issue_at("python:S5799", message, previous, index, source));
            // SonarPython reports one issue per literal, at the first eligible pair.
            break;
        }
    });
    issues
}

fn same_prefix_and_quotes(source: &str, previous: TextRange, current: TextRange) -> bool {
    let previous = &source[previous];
    let current = &source[current];
    let Some(previous_shape) = literal_shape(previous) else {
        return false;
    };
    let Some(current_shape) = literal_shape(current) else {
        return false;
    };
    previous_shape.0.eq_ignore_ascii_case(current_shape.0)
        && previous_shape.1 == current_shape.1
        && previous_shape.2 == current_shape.2
}

fn literal_shape(raw: &str) -> Option<(&str, u8, bool)> {
    let quote_start = raw
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'\'' || *byte == b'"')?;
    let prefix = &raw[..quote_start];
    let quote = raw.as_bytes()[quote_start];
    let triple = raw
        .as_bytes()
        .get(quote_start..quote_start + 3)
        .is_some_and(|slice| slice == [quote, quote, quote]);
    Some((prefix, quote, triple))
}

fn visible_split_exception(source: &str, previous: TextRange, current: TextRange) -> bool {
    let column = source[..previous.start().to_usize()]
        .rsplit_once('\n')
        .map_or(previous.start().to_usize(), |(_, line)| line.len());
    if column + source[previous].len() > MAX_VISIBLE_SPLIT_COLUMN {
        return true;
    }
    let Some(previous_value) = trimmed_literal_value(&source[previous]) else {
        return true;
    };
    let Some(current_value) = trimmed_literal_value(&source[current]) else {
        return true;
    };
    previous_value.ends_with("\\n")
        || previous_value
            .chars()
            .last()
            .is_some_and(|character| character.is_whitespace() || character.is_ascii_punctuation())
        || current_value.starts_with("\\n")
        || current_value
            .chars()
            .next()
            .is_some_and(|character| character.is_whitespace() || character.is_ascii_punctuation())
}

fn trimmed_literal_value(raw: &str) -> Option<&str> {
    let (_, _, triple) = literal_shape(raw)?;
    let quote_start = raw
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'\'' || *byte == b'"')?;
    let quote_len = if triple { 3 } else { 1 };
    (raw.len() >= quote_start + quote_len * 2)
        .then(|| &raw[quote_start + quote_len..raw.len() - quote_len])
}

fn line_number(source: &str, offset: TextSize) -> usize {
    source[..offset.to_usize()]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
}

fn string_context(parsed: &Parsed<ModModule>, target: TextRange) -> (bool, bool) {
    let mut result = None;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |statement| {
        if result.is_some() {
            return;
        }
        for expression in stmt_exprs(statement) {
            if let Some(context) = find_string_context(expression, target, false, false) {
                result = Some(context);
                break;
            }
        }
    });
    result.unwrap_or((false, false))
}

fn find_string_context(
    expr: &Expr,
    target: TextRange,
    parent_is_collection: bool,
    parent_is_blocked: bool,
) -> Option<(bool, bool)> {
    if matches!(expr, Expr::StringLiteral(_) | Expr::BytesLiteral(_)) {
        return (expr.range() == target).then_some((parent_is_collection, parent_is_blocked));
    }
    let child_is_collection = match expr {
        Expr::Call(_) | Expr::List(_) | Expr::Set(_) | Expr::Tuple(_) => true,
        Expr::BinOp(binary) => binary.op == Operator::Add,
        _ => false,
    };
    let child_is_blocked = parent_is_blocked
        || matches!(expr, Expr::Attribute(_))
        || matches!(expr, Expr::BinOp(binary) if binary.op != Operator::Add);
    for child in child_exprs(expr) {
        if let Some(context) =
            find_string_context(child, target, child_is_collection, child_is_blocked)
        {
            return Some(context);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5799_flags_same_style_implicit_concatenation() {
        let bad = scan("merged = 'first' 'second'\n");
        assert_eq!(findings(&bad, "python:S5799").len(), 1);

        let bytes = scan("merged = b'first' b'second'\n");
        assert_eq!(findings(&bytes, "python:S5799").len(), 1);
    }

    #[test]
    fn s5799_ignores_mixed_or_differently_quoted_literals() {
        for clean in [
            "mixed = 'text' b'bytes'\n",
            "quotes = 'first' \"second\"\n",
            "prefix = r'first' 'second'\n",
        ] {
            assert!(findings(&scan(clean), "python:S5799").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s5799_suppresses_multiline_visible_splits_outside_safe_contexts() {
        let clean = "merged = (\n    'first'\n    'second'\n)\n";
        assert!(findings(&scan(clean), "python:S5799").is_empty());
        let collection = "merged = [\n    'first'\n    'second'\n]\n";
        assert_eq!(findings(&scan(collection), "python:S5799").len(), 1);
    }
}
