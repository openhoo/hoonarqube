use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6714 — np.array over a generator -------------------------------------

pub(crate) fn check_np_array_generator(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if matches!(
            dotted_name(&call.func).as_deref(),
            Some("np.array" | "numpy.array")
        ) && let [only] = &call.arguments.args[..]
            && matches!(only, Expr::Generator(_))
        {
            issues.push(issue_at(
                "python:S6714",
                "Pass a materialized sequence to np.array instead of a generator.",
                only.range(),
                index,
                source,
            ));
        }
    }
    issues
}
