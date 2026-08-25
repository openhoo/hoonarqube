use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::stmts_load_any_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7512 — items() when only keys are needed -------------------------------

pub(crate) fn check_items_only_keys_needed(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = stmt else { continue };
        let Expr::Tuple(tuple) = for_stmt.target.as_ref() else {
            continue;
        };
        let [Expr::Name(_), Expr::Name(value)] = &tuple.elts[..] else {
            continue;
        };
        let items_call = matches!(
            for_stmt.iter.as_ref(),
            Expr::Call(call) if matches!(call.func.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "items")
        );
        if items_call && !stmts_load_any_name(&for_stmt.body, &[value.id.to_string()]) {
            issues.push(issue_at(
                "python:S7512",
                "Iterate over the dictionary directly; the value is not used.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    }
    issues
}
