use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::einops_pattern_error;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_einops_patterns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !matches!(
            called_name(&call.func),
            Some("rearrange" | "reduce" | "repeat")
        ) {
            continue;
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
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6984_validates_einops_patterns() {
        let flagged = scan(concat!(
            "rearrange(img, \"b h w -> b w h\")\n",
            "rearrange(img, \"b h -> b w h\")\n",
            "rearrange(img, \"b (h h2 w -> b h w\")\n"
        ));
        assert_eq!(findings(&flagged, "python:S6984").len(), 2);
    }
}
