use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_invalid_weekmask(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const BUSDAY_CALLS: [&str; 4] = [
        "np.busday",
        "np.busday_count",
        "numpy.busday",
        "numpy.busday_count",
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !dotted_name(&call.func).is_some_and(|p| BUSDAY_CALLS.contains(&p.as_str())) {
            continue;
        }
        let mask_position = if dotted_name(&call.func).is_some_and(|p| p.ends_with("busday_count"))
        {
            2
        } else {
            1
        };
        let Some(mask_expr) = keyword_value(&call.arguments, "weekmask")
            .or_else(|| call.arguments.args.get(mask_position))
        else {
            continue;
        };
        if let Some(mask) = string_literal_text(mask_expr)
            && !weekmask_is_valid(&mask)
        {
            issues.push(issue_at(
                "python:S6900",
                "Use a 7-character weekmask containing only '0' and '1'.",
                mask_expr.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- migrated from support/mod.rs (S6900) ---
// --- python:S6900 — invalid NumPy weekmasks ---------------------------------------

fn weekmask_is_valid(mask: &str) -> bool {
    mask.len() == 7 && mask.bytes().all(|byte| byte == b'0' || byte == b'1')
}
