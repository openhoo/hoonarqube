// --- shared literal helpers

use ruff_python_ast::Expr;
use ruff_text_size::Ranged;

/// Whether `expr` is a plain string or bytes literal (static by construction).
pub(crate) fn is_static_text_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::StringLiteral(_) | Expr::BytesLiteral(_))
}

/// Approximate byte length of a string/bytes literal's payload, derived from
/// the raw source slice (escape sequences count as written; good enough for
/// "short static secret" heuristics).
pub(crate) fn static_literal_payload_len(expr: &Expr, source: &str) -> Option<usize> {
    let range = expr.range();
    let raw = source.get(range.start().to_usize()..range.end().to_usize())?;
    let quote = raw.find(['"', '\''])?;
    let closing = raw.rfind(['"', '\''])?;
    Some(closing.saturating_sub(quote).saturating_sub(1))
}
