use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_torch_load_weights_only(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
