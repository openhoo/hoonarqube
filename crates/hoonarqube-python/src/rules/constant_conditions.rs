use crate::support::constant_truth;
use crate::support::for_each_stmt;
use crate::support::is_true_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_conditions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let test = match stmt {
            Stmt::If(if_stmt) => Some(&if_stmt.test),
            Stmt::While(while_stmt) => Some(&while_stmt.test),
            _ => None,
        };
        if let Some(test) = test
            && constant_truth(test).is_some()
            && !(matches!(stmt, Stmt::While(_)) && is_true_literal(test))
        {
            issues.push(issue_at(
                "python:S5797",
                "Replace this constant condition with real logic.",
                test.range(),
                index,
                source,
            ));
        }
    });
    issues
}
