// --- python:S6969 / S6973 / S6971 — scikit-learn contracts

use crate::support::{called_name, for_each_stmt, has_keyword};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

pub(crate) fn required_estimator_parameters(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "KMeans" => Some(&["n_clusters"]),
        "PCA" | "TruncatedSVD" | "NMF" => Some(&["n_components"]),
        "SGDClassifier" | "SGDRegressor" => Some(&["max_iter", "tol"]),
        _ => None,
    }
}

/// Names bound to `Pipeline(...)` constructions that enable caching.
pub(crate) fn collect_caching_pipeline_variables(module_body: &[Stmt]) -> Vec<String> {
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func) == Some("Pipeline")
            && has_keyword(&call.arguments, "memory")
        {
            names.push(target.id.to_string());
        }
    });
    names
}
