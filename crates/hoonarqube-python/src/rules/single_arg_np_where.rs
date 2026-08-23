use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6729 — single-argument np.where ------------------------------------

pub(crate) fn check_single_arg_np_where(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if matches!(
            dotted_name(&call.func).as_deref(),
            Some("np.where" | "numpy.where")
        ) && call.arguments.args.len() == 1
            && call.arguments.keywords.is_empty()
        {
            issues.push(issue_at(
                "python:S6729",
                "Prefer np.nonzero over a single-argument np.where.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
