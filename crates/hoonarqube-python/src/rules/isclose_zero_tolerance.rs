use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_zero_number_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6727 — math.isclose against zero without abs_tol -------------------

pub(crate) fn check_isclose_zero_tolerance(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).as_deref() != Some("math.isclose") {
            return;
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
    });
    issues
}
