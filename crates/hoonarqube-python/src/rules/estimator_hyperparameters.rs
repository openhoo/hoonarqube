use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use crate::support::required_estimator_parameters;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_estimator_hyperparameters(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(name) = called_name(&call.func) else {
            continue;
        };
        let Some(required) = required_estimator_parameters(name) else {
            continue;
        };
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|parameter| !has_keyword(&call.arguments, parameter))
            .collect();
        if !missing.is_empty() {
            issues.push(issue_at(
                "python:S6973",
                &format!(
                    "Initialize this estimator with required hyperparameters: {}.",
                    missing.join(", ")
                ),
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6973_flags_estimators_missing_required_hyperparameters() {
        let flagged = scan("KMeans(3)\nKMeans(n_clusters=3)\nPCA(4)\nSGDClassifier(max_iter=5)\n");
        assert_eq!(findings(&flagged, "python:S6973").len(), 3);
    }
}
