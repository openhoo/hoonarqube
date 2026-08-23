use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5706 — `__exit__` re-raising the provided exception --------------

pub(crate) fn check_exit_reraises_argument(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        if function.name.as_str() != "__exit__" {
            return;
        }
        let arguments: Vec<String> = positional_parameters(&function.parameters)
            .iter()
            .skip(1)
            .map(|parameter| parameter.name.to_string())
            .collect();
        for_each_stmt_in_scope(&function.body, &mut |inner| {
            if let Stmt::Raise(raised) = inner
                && let Some(Expr::Name(name)) = raised.exc.as_deref()
                && arguments.contains(&name.id.to_string())
            {
                issues.push(issue_at(
                    "python:S5706",
                    "Remove this 'raise'; '__exit__' must not re-raise the exception argument.",
                    raised.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
