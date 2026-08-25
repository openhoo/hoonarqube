use crate::engine::file_context::FileContext;
use crate::support::flag_trailing_continue;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3626 — redundant jump statements --------------------------------

pub(crate) fn check_redundant_jump_statements(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        match stmt {
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
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s3626_flags_trailing_jump_statements() {
        let cases = [
            ("def f():\n    setup()\n    return\n", 3),
            ("for i in xs:\n    step(i)\n    continue\n", 3),
            ("match x:\n    case 1:\n        break\n", 3),
        ];
        for (source, line) in cases {
            let report = scan(source);
            let found = findings(&report, "python:S3626");
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].range.start.line, line);
        }
        let clean = "def f():\n    if a:\n        return 0\n    return 1\n";
        assert!(findings(&scan(clean), "python:S3626").is_empty());
    }
}
