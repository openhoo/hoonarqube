use crate::engine::file_context::FileContext;
use crate::support::{comparison_pairs, issue_at, stmt_store_names};
use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{CmpOp, Expr, ModModule, Number};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S5795 — identity comparison with cached types -------------------
pub(crate) fn check_s5795_identity_cached_types(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        for (op, lhs, rhs) in comparison_pairs(compare) {
            if !matches!(op, CmpOp::Is | CmpOp::IsNot)
                || is_none_literal(lhs)
                || is_none_literal(rhs)
                || (!is_concrete_cached_type(lhs, file_ctx)
                    && !is_concrete_cached_type(rhs, file_ctx))
            {
                continue;
            }
            let Some(operator_range) =
                identity_operator_range(parsed, lhs.range(), rhs.range(), op)
            else {
                continue;
            };
            let message = match op {
                CmpOp::Is => {
                    "Replace this \"is\" operator with \"==\"; identity operator is not reliable here."
                }
                CmpOp::IsNot => {
                    "Replace this \"is not\" operator with \"!=\"; identity operator is not reliable here."
                }
                _ => continue,
            };
            issues.push(issue_at(
                "python:S5795",
                message,
                operator_range,
                index,
                source,
            ));
        }
    }
    issues
}
fn is_none_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::NoneLiteral(_))
}
fn is_concrete_cached_type(expr: &Expr, file_ctx: &FileContext) -> bool {
    match expr {
        Expr::NumberLiteral(number) => matches!(number.value, Number::Int(_) | Number::Float(_)),
        Expr::StringLiteral(_) | Expr::BytesLiteral(_) | Expr::Tuple(_) => true,
        Expr::Call(call) => matches!(call.func.as_ref(), Expr::Name(name)
            if matches!(name.id.as_str(), "frozenset" | "bytes" | "int" | "float" | "str" | "tuple" | "hash")
                && cached_unshadowed(file_ctx, call.range(), name.id.as_str())),
        _ => false,
    }
}
fn cached_unshadowed(ctx: &FileContext, call_range: TextRange, name: &str) -> bool {
    !ctx.stmts
        .iter()
        .filter(|stmt| {
            !ctx.functions.iter().any(|f| {
                f.range().contains(stmt.range().start()) && !f.range().contains(call_range.start())
            })
        })
        .any(|stmt| stmt_store_names(stmt).iter().any(|stored| stored == name))
}
fn identity_operator_range(
    parsed: &Parsed<ModModule>,
    left: TextRange,
    right: TextRange,
    op: CmpOp,
) -> Option<TextRange> {
    let from = left.end();
    let to = right.start();
    let mut tokens = parsed
        .tokens()
        .iter()
        .filter(|token| token.range().start() >= from && token.range().end() <= to);
    match op {
        CmpOp::Is => tokens
            .find(|token| token.kind() == TokenKind::Is)
            .map(Ranged::range),
        CmpOp::IsNot => {
            let mut is_range = None;
            for token in tokens {
                if token.kind() == TokenKind::Is {
                    is_range = Some(token.range());
                } else if token.kind() == TokenKind::Not {
                    return Some(TextRange::new(is_range?.start(), token.range().end()));
                }
            }
            None
        }
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};
    #[test]
    fn s5795_flags_cached_literals_and_keeps_none_safe() {
        let flagged = scan("if x is 5:\n    pass\nif y is not \"v\":\n    pass\n");
        let issues = findings(&flagged, "python:S5795");
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .any(|issue| issue.message.contains("is not") && issue.message.contains("!="))
        );
        let clean = scan("if z is None:\n    pass\nif a == 5:\n    pass\n");
        assert!(findings(&clean, "python:S5795").is_empty());
    }
    #[test]
    fn s5795_flags_only_concrete_cached_shapes() {
        assert_eq!(
            findings(&scan("value = (1, 2) is other\n"), "python:S5795").len(),
            1
        );
        assert_eq!(
            findings(&scan("value = frozenset() is other\n"), "python:S5795").len(),
            1
        );
        assert!(findings(&scan("value = f\"{x}\" is other\n"), "python:S5795").is_empty());
        assert!(findings(&scan("value = 1j is other\n"), "python:S5795").is_empty());
    }
}
