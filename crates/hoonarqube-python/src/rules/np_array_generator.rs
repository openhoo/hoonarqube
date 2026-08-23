use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6714 — np.array over a generator -------------------------------------

pub(crate) fn check_np_array_generator(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
