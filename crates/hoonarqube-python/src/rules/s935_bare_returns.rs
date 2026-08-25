use crate::engine::calls::concrete_hint;
use crate::engine::file_context::FileContext;
use crate::support::expr_normalized_text;
use crate::support::for_each_return_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S935 — functions should only return expected values ---------------

/// python:S935 — bare `return` inside a file-local function annotated with a
/// concrete non-Optional builtin type hands back an implicit `None`.
pub(crate) fn check_s935_bare_returns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        let Some(annotation) = function.returns.as_deref() else {
            continue;
        };
        if concrete_hint(annotation).is_none() {
            continue;
        }
        let annotation_text = expr_normalized_text(annotation, source);
        for_each_return_in_scope(&function.body, &mut |returned| {
            if returned.value.is_none() {
                issues.push(issue_at(
                    "python:S935",
                    &format!(
                        "This bare 'return' conflicts with the '{annotation_text}' \
                         return type; return a value or make it Optional."
                    ),
                    returned.range(),
                    index,
                    source,
                ));
            }
        });
    }
    issues
}
