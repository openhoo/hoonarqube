use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6663_sequence_index_type(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const SEQUENCE_LITERALS: [&str; 3] = ["list", "tuple", "string"];
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::Subscript(subscript) = expr {
            let sequence_kind = literal_kind(subscript.value.as_ref());
            let index_kind = literal_kind(subscript.slice.as_ref());
            let bad_index = matches!(index_kind, Some("string" | "bytes"))
                || is_float_literal(subscript.slice.as_ref());
            if SEQUENCE_LITERALS.contains(&sequence_kind.unwrap_or_default()) && bad_index {
                issues.push(issue_at(
                    "python:S6663",
                    "Use an integer index into this sequence.",
                    expr.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- migrated from support/mod.rs (S6663) ---
// --- python:S6663 — sequence indexes must provide __index__ ------------------------

fn is_float_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(number.value, ruff_python_ast::Number::Float(_))
    )
}
