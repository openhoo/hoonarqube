use crate::support::COMPARISON_ASSERTS;
use crate::support::assertion_literal_kind;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5845 — assertions on incompatible literal types -------------------

pub(crate) fn check_incompatible_assert_literals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func).is_some_and(|name| COMPARISON_ASSERTS.contains(&name))
            && let [left, right] = &call.arguments.args[..]
            && let (Some(left_kind), Some(right_kind)) =
                (assertion_literal_kind(left), assertion_literal_kind(right))
            && left_kind != right_kind
        {
            issues.push(issue_at(
                "python:S5845",
                "This assertion compares literals of different types.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
