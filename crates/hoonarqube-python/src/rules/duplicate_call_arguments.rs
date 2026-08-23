use crate::support::exprs_textually_equal;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::trivially_repeatable;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_duplicate_call_arguments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let arguments = &call.arguments.args;
        'outer: for left in arguments {
            for right in arguments {
                if std::ptr::eq(left, right) {
                    continue;
                }
                if exprs_textually_equal(left, right, source) && !trivially_repeatable(left, right)
                {
                    issues.push(issue_at(
                        "python:S5549",
                        "This identical argument appears more than once.",
                        call.range(),
                        index,
                        source,
                    ));
                    break 'outer;
                }
            }
        }
    });
    issues
}
