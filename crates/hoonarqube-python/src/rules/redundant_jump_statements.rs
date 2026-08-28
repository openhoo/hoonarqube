use crate::engine::file_context::FileContext;
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
        if let Stmt::FunctionDef(function) = stmt
            && let Some(Stmt::Return(last)) = function.body.last()
            && last.value.as_deref().is_none_or(is_none_literal)
        {
            issues.push(issue_at(
                "python:S3626",
                "Remove this redundant return.",
                last.range(),
                index,
                source,
            ));
        }
    }
    issues
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
        let clean = concat!(
            "def f():\n    if a:\n        return 0\n    return 1\n",
            "for i in xs:\n    step(i)\n    continue\n",
            "match x:\n    case 1:\n        break\n"
        );
        assert!(findings(&scan(clean), "python:S3626").is_empty());
    }
}
