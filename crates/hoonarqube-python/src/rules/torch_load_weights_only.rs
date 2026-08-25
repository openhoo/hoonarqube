use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_torch_load_weights_only(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name(&call.func).as_deref() == Some("torch.load")
            && !has_keyword(&call.arguments, "weights_only")
        {
            issues.push(issue_at(
                "python:S6985",
                "Pass weights_only=True to torch.load.",
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
    fn s6985_requires_weights_only_on_torch_load() {
        let flagged = scan("torch.load(\"m.pt\")\ntorch.load(\"m.pt\", weights_only=True)\n");
        assert_eq!(findings(&flagged, "python:S6985").len(), 1);
    }
}
