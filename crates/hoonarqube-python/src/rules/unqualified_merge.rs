use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unqualified_merge(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if !matches!(called_name(&call.func), Some("merge" | "join")) {
            return;
        }
        let qualified = ["on", "left_on", "right_on", "how", "validate"]
            .iter()
            .any(|name| has_keyword(&call.arguments, name));
        if !qualified {
            issues.push(issue_at(
                "python:S6735",
                "Make this join explicit with on/how or validate arguments.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
