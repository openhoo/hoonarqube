use crate::support::PROTOCOL_DUNDERS;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_notimplemented_error_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_notimplemented_raises(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && PROTOCOL_DUNDERS.contains(&function.name.as_str())
        {
            for_each_stmt_in_scope(&function.body, &mut |inner| {
                if let Stmt::Raise(raised) = inner
                    && raised
                        .exc
                        .as_deref()
                        .is_some_and(is_notimplemented_error_expr)
                {
                    issues.push(issue_at(
                        "python:S5712",
                        "Return 'NotImplemented' instead of raising 'NotImplementedError'.",
                        raised.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}
