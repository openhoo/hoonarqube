use crate::support::for_each_stmt_expr;
use crate::support::is_float_literal;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6663_sequence_index_type(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const SEQUENCE_LITERALS: [&str; 3] = ["list", "tuple", "string"];
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
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
    });
    issues
}
