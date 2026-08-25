use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_reduction_axis_missing(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let Some(path) = dotted_name(&call.func) else {
            return;
        };
        let reduction = path.starts_with("tf.reduce_") || NUMPY_REDUCTIONS.contains(&path.as_str());
        if reduction && !has_keyword(&call.arguments, "axis") && call.arguments.args.len() < 2 {
            issues.push(issue_at(
                "python:S6929",
                "Specify the reduction axis explicitly.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S6929) ---
// --- python:S6929 / python:S6925 — TensorFlow reduction/gather contracts -------------

const NUMPY_REDUCTIONS: [&str; 18] = [
    "np.sum",
    "np.mean",
    "np.max",
    "np.min",
    "np.prod",
    "np.std",
    "np.var",
    "np.all",
    "np.any",
    "numpy.sum",
    "numpy.mean",
    "numpy.max",
    "numpy.min",
    "numpy.prod",
    "numpy.std",
    "numpy.var",
    "numpy.all",
    "numpy.any",
];
