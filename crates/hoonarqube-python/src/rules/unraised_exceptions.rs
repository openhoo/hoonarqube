use crate::support::exception_constructor_name;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unraised_exceptions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_in_scope(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Expr(expr) = stmt
            && let Expr::Call(call) = expr.value.as_ref()
            && let Some(name) = exception_constructor_name(call)
        {
            issues.push(issue_at(
                "python:S3984",
                &format!("Raise this '{name}' exception instead of creating it."),
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s3984_flags_exceptions_created_without_raising() {
        let flagged = scan(
            "ValueError(\"bad\")\nraise ValueError(\"good\")\nstored = ValueError(\"kept\")\n",
        );
        assert_eq!(findings(&flagged, "python:S3984").len(), 1);
    }
}
