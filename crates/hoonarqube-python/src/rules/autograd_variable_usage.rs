use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6979 / S6983 / S6985 / S6984 — PyTorch/einops contracts ------------------

pub(crate) fn check_autograd_variable_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).as_deref() == Some("torch.autograd.Variable") {
            issues.push(issue_at(
                "python:S6979",
                "Replace torch.autograd.Variable with torch.tensor.",
                call.range(),
                index,
                source,
            ));
        }
    });
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
