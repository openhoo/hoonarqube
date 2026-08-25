use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7507 — defaultdict default_factory keyword --------------------------

pub(crate) fn check_defaultdict_keyword_factory(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        if called_name(&call.func) != Some("defaultdict") {
            continue;
        }
        for keyword in &call.arguments.keywords {
            if keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "default_factory")
            {
                issues.push(issue_at(
                    "python:S7507",
                    "Pass the default factory positionally; 'default_factory' is not a valid keyword.",
                    keyword.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
