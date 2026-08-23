use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::single_positional_call;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7510/S7511/S7516 — sorted/reversed call shapes ----------------------

pub(crate) fn check_sorted_reversed_shapes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        // S7510: reversed(sorted(x))
        if let Some(argument) = single_positional_call(expr, "reversed")
            && single_positional_call(argument, "sorted").is_some()
        {
            issues.push(issue_at(
                "python:S7510",
                "Sort descending directly with 'sorted(..., reverse=True)'.",
                expr.range(),
                index,
                source,
            ));
            return;
        }
        // S7516: set(sorted(x))
        if let Some(argument) = single_positional_call(expr, "set")
            && single_positional_call(argument, "sorted").is_some()
        {
            issues.push(issue_at(
                "python:S7516",
                "Sorting before 'set' is pointless; the order is discarded.",
                expr.range(),
                index,
                source,
            ));
            return;
        }
        // S7511: set(reversed(x)) / sorted(reversed(x)) / reversed(reversed(x))
        for wrapper in ["set", "sorted"] {
            if let Some(argument) = single_positional_call(expr, wrapper)
                && single_positional_call(argument, "reversed").is_some()
            {
                issues.push(issue_at(
                    "python:S7511",
                    "The 'reversed' call has no effect on the result here.",
                    expr.range(),
                    index,
                    source,
                ));
                return;
            }
        }
        if let Some(argument) = single_positional_call(expr, "reversed")
            && single_positional_call(argument, "reversed").is_some()
        {
            issues.push(issue_at(
                "python:S7511",
                "The 'reversed' call has no effect on the result here.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
