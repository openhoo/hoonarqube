use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_dataloader_workers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("DataLoader")
            && !has_keyword(&call.arguments, "num_workers")
        {
            issues.push(issue_at(
                "python:S6983",
                "Pass num_workers to parallelize this DataLoader.",
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
    fn s6983_requires_num_workers_on_dataloaders() {
        let flagged = scan("DataLoader(ds, batch_size=2)\nDataLoader(ds, num_workers=4)\n");
        assert_eq!(findings(&flagged, "python:S6983").len(), 1);
    }
}
