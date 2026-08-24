use crate::support::flag_duplicate_branches;
use crate::support::for_each_stmt;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S1871 — duplicate conditional branches ---------------------------

pub(crate) fn check_duplicate_branches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::If(if_stmt) => {
            let mut branches: Vec<&[Stmt]> = vec![&if_stmt.body];
            branches.extend(
                if_stmt
                    .elif_else_clauses
                    .iter()
                    .map(|clause| clause.body.as_slice()),
            );
            flag_duplicate_branches(&branches, "python:S1871", &mut issues, index, source);
        }
        Stmt::Try(try_stmt) => {
            let handlers: Vec<&[Stmt]> = try_stmt
                .handlers
                .iter()
                .map(|handler| match handler {
                    ExceptHandler::ExceptHandler(inner) => inner.body.as_slice(),
                })
                .collect();
            flag_duplicate_branches(&handlers, "python:S1871", &mut issues, index, source);
        }
        _ => {}
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1871_flags_duplicate_branch_bodies() {
        let chain = scan("if a == 1:\n    do(x)\nelif a == 2:\n    do(x)\n");
        let found = findings(&chain, "python:S1871");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let handlers =
            scan("try:\n    risky()\nexcept A:\n    handle()\nexcept B:\n    handle()\n");
        assert_eq!(findings(&handlers, "python:S1871").len(), 1);
        let clean = "if a == 1:\n    do(x)\nelif a == 2:\n    do(y)\n";
        assert!(findings(&scan(clean), "python:S1871").is_empty());
    }
}
