use crate::rules::suite::check_suite;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_nested_bodies(
    stmt: &ruff_python_ast::Stmt,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    use ruff_python_ast::{ExceptHandler, Stmt};
    match stmt {
        Stmt::FunctionDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::ClassDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::For(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::While(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::If(s) => {
            check_suite(&s.body, issues, index, source);
            for clause in &s.elif_else_clauses {
                check_suite(&clause.body, issues, index, source);
            }
        }
        Stmt::With(s) => check_suite(&s.body, issues, index, source),
        Stmt::Match(s) => {
            for case in &s.cases {
                check_suite(&case.body, issues, index, source);
            }
        }
        Stmt::Try(s) => {
            check_suite(&s.body, issues, index, source);
            for handler in &s.handlers {
                match handler {
                    ExceptHandler::ExceptHandler(handler) => {
                        check_suite(&handler.body, issues, index, source);
                    }
                }
            }
            check_suite(&s.orelse, issues, index, source);
            check_suite(&s.finalbody, issues, index, source);
        }
        _ => {}
    }
}
