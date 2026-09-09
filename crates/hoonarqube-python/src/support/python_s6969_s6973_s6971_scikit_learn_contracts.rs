// --- python:S6969 / S6973 / S6971 — scikit-learn contracts

pub(crate) fn required_estimator_parameters(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "KMeans" => Some(&["n_clusters"]),
        "PCA" | "TruncatedSVD" | "NMF" => Some(&["n_components"]),
        "SGDClassifier" | "SGDRegressor" => Some(&["max_iter", "tol"]),
        _ => None,
    }
}
