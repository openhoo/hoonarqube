use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5042 — archive extraction without resource control ---------------

pub(crate) fn check_unbounded_archive_extraction(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let archive_bindings: std::collections::HashMap<&str, ruff_text_size::TextRange> = file_ctx
        .stmts
        .iter()
        .filter_map(|stmt| {
            let Stmt::Assign(assign) = stmt else {
                return None;
            };
            let [Expr::Name(target)] = assign.targets.as_slice() else {
                return None;
            };
            let Expr::Call(open) = assign.value.as_ref() else {
                return None;
            };
            (dotted_name(&open.func).as_deref() == Some("tarfile.open"))
                .then_some((target.id.as_str(), open.func.range()))
        })
        .collect();
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("extractall") && !has_keyword(&call.arguments, "members")
        {
            let range = match call.func.as_ref() {
                Expr::Attribute(attribute) => match attribute.value.as_ref() {
                    Expr::Name(receiver) => archive_bindings
                        .get(receiver.id.as_str())
                        .copied()
                        .unwrap_or_else(|| call.func.range()),
                    _ => call.func.range(),
                },
                _ => call.func.range(),
            };
            issues.push(issue_at(
                "python:S5042",
                "Make sure that expanding this archive file is safe here.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}
