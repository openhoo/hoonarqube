use crate::support::ROUTE_DECORATOR_TAILS;
use crate::support::decorator_callee_path;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_route_decorator_ordering(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            let last = function.decorator_list.len().saturating_sub(1);
            for (position, decorator) in function.decorator_list.iter().enumerate() {
                let tail = decorator_callee_path(&decorator.expression)
                    .and_then(|path| path.rsplit('.').next().map(str::to_string))
                    .unwrap_or_default();
                if ROUTE_DECORATOR_TAILS.contains(&tail.as_str()) && position < last {
                    issues.push(issue_at(
                        "python:S6552",
                        "Place the routing decorator outermost.",
                        decorator.expression.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
