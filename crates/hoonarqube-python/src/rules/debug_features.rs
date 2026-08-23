use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4507 — debug features left enabled --------------------------------

pub(crate) fn check_debug_features(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const DEBUG_CALLS: [&str; 4] = [
        "breakpoint",
        "pdb.set_trace",
        "ipdb.set_trace",
        "celery.contrib.rdb.set_trace",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let debug_call =
            dotted_name(&call.func).is_some_and(|path| DEBUG_CALLS.contains(&path.as_str()));
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
    });
    issues
}
