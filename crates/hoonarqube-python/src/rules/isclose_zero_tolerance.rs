use crate::engine::file_context::FileContext;
use crate::support::dotted_name_is;
use crate::support::has_keyword;
use crate::support::is_zero_number_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6727 — math.isclose against zero without abs_tol -------------------

pub(crate) fn check_isclose_zero_tolerance(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !dotted_name_is(&call.func, "math.isclose") {
            continue;
        }
        let compares_zero = call.arguments.args.iter().any(is_zero_number_literal)
            || keyword_value(&call.arguments, "rel_tol").is_some_and(is_zero_number_literal);
        if compares_zero && !has_keyword(&call.arguments, "abs_tol") {
            issues.push(issue_at(
                "python:S6727",
                "Add an abs_tol to compare this value against zero precisely.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
