use crate::support::direct_constant_return_texts;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_invariant_returns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_in_scope(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            let returns = direct_constant_return_texts(&function.body, source);
            let identical = returns.len() >= 2 && returns.windows(2).all(|pair| pair[0] == pair[1]);
            if identical {
                issues.push(issue_at(
                    "python:S3516",
                    "Every return path yields the same constant; verify this is intended.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
