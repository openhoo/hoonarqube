use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6979 / S6983 / S6985 / S6984 — PyTorch/einops contracts ------------------

pub(crate) fn check_autograd_variable_usage(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name(&call.func).as_deref() == Some("torch.autograd.Variable") {
            issues.push(issue_at(
                "python:S6979",
                "Replace torch.autograd.Variable with torch.tensor.",
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
    fn s6979_flags_autograd_variable_usage() {
        let flagged = scan("torch.autograd.Variable(x)\n");
        assert_eq!(findings(&flagged, "python:S6979").len(), 1);
    }
}
