use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4507 — debug features left enabled --------------------------------

pub(crate) fn check_debug_features(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const DEBUG_CALLS: [&str; 4] = [
        "breakpoint",
        "pdb.set_trace",
        "ipdb.set_trace",
        "celery.contrib.rdb.set_trace",
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let debug_call = dotted_name_in(&call.func, &DEBUG_CALLS);
        let debug_flag = keyword_value(&call.arguments, "debug").is_some_and(is_true_literal);
        if debug_call || debug_flag {
            issues.push(issue_at(
                "python:S4507",
                "Remove this debug feature before shipping to production.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
