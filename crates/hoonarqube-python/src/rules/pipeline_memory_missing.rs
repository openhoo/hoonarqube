use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pipeline_memory_missing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("Pipeline") && !has_keyword(&call.arguments, "memory") {
            issues.push(issue_at(
                "python:S6969",
                "Pass a memory directory to enable Pipeline caching.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- migrated from support/mod.rs (S6969) ---
// --- python:S6969 / S6973 / S6971 — scikit-learn contracts ---------------------------

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6969_requires_memory_on_pipelines() {
        let flagged = scan("Pipeline(steps)\nPipeline(steps, memory=\"./cache\")\n");
        assert_eq!(findings(&flagged, "python:S6969").len(), 1);
    }
}
