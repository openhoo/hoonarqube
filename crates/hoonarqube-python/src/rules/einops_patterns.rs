use crate::support::called_name;
use crate::support::einops_pattern_error;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_einops_patterns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if !matches!(
            called_name(&call.func),
            Some("rearrange" | "reduce" | "repeat")
        ) {
            return;
        }
        // The pattern is the second positional argument (after the tensor).
        if let Some(pattern_expr) = call
            .arguments
            .args
            .get(1)
            .or_else(|| keyword_value(&call.arguments, "pattern"))
            && let Some(pattern) = string_literal_text(pattern_expr)
            && let Some(error) = einops_pattern_error(&pattern)
        {
            issues.push(issue_at(
                "python:S6984",
                &format!("Fix this invalid einops pattern: {error}."),
                pattern_expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
