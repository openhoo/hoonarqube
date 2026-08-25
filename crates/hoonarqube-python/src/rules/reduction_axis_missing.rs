use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_reduction_axis_missing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(path) = dotted_name(&call.func) else {
            continue;
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
    }
    issues
}

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
