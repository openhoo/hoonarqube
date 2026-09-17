use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3626 — redundant jump statements --------------------------------

/// Which boundary makes a trailing jump redundant: the end of the enclosing
/// function for `return`, the next iteration of the enclosing loop for
/// `continue`. `None` marks positions where no jump is redundant.
#[derive(Clone, Copy, PartialEq)]
enum Tail {
    None,
    Function,
    Loop,
}

pub(crate) fn check_redundant_jump_statements(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_suite(file_ctx.module_body, Tail::None, false, &mut |stmt| {
        let kind = match stmt {
            Stmt::Return(return_stmt) if return_stmt.value.is_none() => "return",
            Stmt::Continue(_) => "continue",
            _ => return,
        };
        issues.push(issue_at(
            "python:S3626",
            &format!("Remove this redundant {kind}."),
            stmt.range(),
            index,
            source,
        ));
    });
    issues
}

/// Visits bare `return`/`continue` statements that sit in tail position of
/// their boundary, mirroring the reference `RedundantJumpCheck` CFG rule: a
/// jump is redundant only when its block flows straight into the syntactic
/// successor. Exemptions match the reference: `return` with an expression
/// (including `return None`), jumps that are the only statement of their
/// block, and anything under a `try` ancestor (imprecise CFG).
fn walk_suite(suite: &[Stmt], tail: Tail, in_try: bool, flag: &mut dyn FnMut(&Stmt)) {
    for (position, stmt) in suite.iter().enumerate() {
        let is_last = position + 1 == suite.len();
        let child_tail = if is_last { tail } else { Tail::None };
        match stmt {
            Stmt::Return(return_stmt) => {
                if !in_try
                    && tail == Tail::Function
                    && is_last
                    && suite.len() > 1
                    && return_stmt.value.is_none()
                {
                    flag(stmt);
                }
            }
            Stmt::Continue(_) => {
                if !in_try && tail == Tail::Loop && is_last && suite.len() > 1 {
                    flag(stmt);
                }
            }
            Stmt::FunctionDef(function) => {
                walk_suite(&function.body, Tail::Function, in_try, flag);
            }
            Stmt::ClassDef(class) => {
                walk_suite(&class.body, Tail::None, in_try, flag);
            }
            Stmt::If(if_stmt) => {
                walk_suite(&if_stmt.body, child_tail, in_try, flag);
                for clause in &if_stmt.elif_else_clauses {
                    walk_suite(&clause.body, child_tail, in_try, flag);
                }
            }
            Stmt::For(for_stmt) => {
                walk_suite(&for_stmt.body, Tail::Loop, in_try, flag);
                walk_suite(&for_stmt.orelse, child_tail, in_try, flag);
            }
            Stmt::While(while_stmt) => {
                walk_suite(&while_stmt.body, Tail::Loop, in_try, flag);
                walk_suite(&while_stmt.orelse, child_tail, in_try, flag);
            }
            Stmt::With(with_stmt) => {
                walk_suite(&with_stmt.body, child_tail, in_try, flag);
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    walk_suite(&case.body, child_tail, in_try, flag);
                }
            }
            Stmt::Try(try_stmt) => {
                walk_suite(&try_stmt.body, Tail::None, true, flag);
                walk_suite(&try_stmt.orelse, Tail::None, true, flag);
                walk_suite(&try_stmt.finalbody, Tail::None, true, flag);
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    walk_suite(&handler.body, Tail::None, true, flag);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s3626_flags_trailing_jump_statements() {
        let report = scan("def f():\n    setup()\n    return\n");
        let found = findings(&report, "python:S3626");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        // `return` carrying an expression (even `None`), jumps that are the
        // only statement of their block, and anything under a `try` ancestor
        // are exempt in the reference implementation.
        let clean = concat!(
            "def f():\n    if a:\n        return 0\n    return 1\n",
            "def g():\n    if a:\n        return\n",
            "def h():\n    try:\n        work()\n        return\n    except E:\n        pass\n",
            "def k():\n    if a:\n        return None\n",
        );
        assert!(findings(&scan(clean), "python:S3626").is_empty());
        // A `continue` ending a multi-statement loop body is redundant.
        let flagged = scan("for i in xs:\n    step(i)\n    continue\n");
        assert_eq!(findings(&flagged, "python:S3626").len(), 1);
        // `break` is never redundant and a sole-statement `continue` is exempt.
        let clean = concat!(
            "match x:\n    case 1:\n        break\n",
            "for i in xs:\n    if i:\n        continue\n",
        );
        assert!(findings(&scan(clean), "python:S3626").is_empty());
    }
}
