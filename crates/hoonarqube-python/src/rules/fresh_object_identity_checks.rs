use crate::engine::file_context::FileContext;
use crate::support::{comparison_pairs, function_parameters, issue_at, stmt_store_names};
use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{CmpOp, Expr, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S5796 — identity check on freshly created objects ----------------
pub(crate) fn check_fresh_object_identity_checks(
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
        for (op, left, right) in comparison_pairs(compare) {
            if !matches!(op, CmpOp::Is | CmpOp::IsNot)
                || is_none(left)
                || is_none(right)
                || (!fresh(left, file_ctx) && !fresh(right, file_ctx))
            {
                continue;
            }
            let Some(span) = operator_range(parsed, left.range(), right.range(), op) else {
                continue;
            };
            let message = match op {
                CmpOp::Is => "Replace this \"is\" operator with \"==\".",
                CmpOp::IsNot => "Replace this \"is not\" operator with \"!=\".",
                _ => continue,
            };
            issues.push(issue_at("python:S5796", message, span, index, source));
        }
    }
    issues
}
fn is_none(expr: &Expr) -> bool {
    matches!(expr, Expr::NoneLiteral(_))
}
fn fresh(expr: &Expr, ctx: &FileContext) -> bool {
    match expr {
        Expr::Dict(_)
        | Expr::DictComp(_)
        | Expr::List(_)
        | Expr::ListComp(_)
        | Expr::Set(_)
        | Expr::SetComp(_) => true,
        Expr::Call(call) => matches!(call.func.as_ref(), Expr::Name(name)
            if matches!(name.id.as_str(), "dict" | "list" | "set" | "complex") && unshadowed(ctx, call.range(), name.id.as_str())),
        _ => false,
    }
}
fn unshadowed(ctx: &FileContext, call_range: TextRange, name: &str) -> bool {
    let scope = ctx
        .functions
        .iter()
        .filter(|f| f.range().contains(call_range.start()))
        .min_by_key(|f| f.range().len());
    if scope.is_some_and(|f| {
        function_parameters(f)
            .iter()
            .any(|p| p.parameter.name.as_str() == name)
    }) {
        return false;
    }
    !ctx.stmts
        .iter()
        .filter(|stmt| match scope {
            Some(function) => {
                function.range().contains(stmt.range().start())
                    && function.range().contains(stmt.range().end())
            }
            None => !ctx
                .functions
                .iter()
                .any(|function| function.range().contains(stmt.range().start())),
        })
        .any(|stmt| stmt_store_names(stmt).iter().any(|stored| stored == name))
}
fn operator_range(
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
        .filter(|t| t.range().start() >= from && t.range().end() <= to);
    match op {
        CmpOp::Is => tokens
            .find(|t| t.kind() == TokenKind::Is)
            .map(Ranged::range),
        CmpOp::IsNot => {
            let mut is = None;
            for t in tokens {
                if t.kind() == TokenKind::Is {
                    is = Some(t.range());
                } else if t.kind() == TokenKind::Not {
                    return Some(TextRange::new(is?.start(), t.range().end()));
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
    fn s5796_flags_pinned_fresh_objects_with_operator_specific_messages() {
        let report = scan("never = [] is []\nnot_never = list() is not other\n");
        let issues = findings(&report, "python:S5796");
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("is not") && i.message.contains("!="))
        );
    }
    #[test]
    fn s5796_keeps_non_pinned_or_none_shapes_without_findings() {
        for clean in [
            "tupled = () is other\n",
            "generated = (x for x in xs) is other\n",
            "frozen = frozenset() is other\n",
            "known = value is other\n",
            "none = [] is None\n",
        ] {
            assert!(findings(&scan(clean), "python:S5796").is_empty(), "{clean}");
        }
    }
}
