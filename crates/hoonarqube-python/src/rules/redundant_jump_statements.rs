use crate::support::flag_trailing_continue;
use crate::support::for_each_stmt;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3626 — redundant jump statements --------------------------------

pub(crate) fn check_redundant_jump_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => {
            if let Some(Stmt::Return(last)) = function.body.last()
                && last.value.as_deref().is_none_or(is_none_literal)
            {
                issues.push(issue_at(
                    "python:S3626",
                    "Remove this redundant jump statement.",
                    last.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::For(for_stmt) => {
            flag_trailing_continue(&for_stmt.body, &mut issues, index, source);
        }
        Stmt::While(while_stmt) => {
            flag_trailing_continue(&while_stmt.body, &mut issues, index, source);
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                if let Some(Stmt::Break(last)) = case.body.last() {
                    issues.push(issue_at(
                        "python:S3626",
                        "Remove this redundant jump statement.",
                        last.range(),
                        index,
                        source,
                    ));
                }
            }
        }
        _ => {}
    });
    issues
}
