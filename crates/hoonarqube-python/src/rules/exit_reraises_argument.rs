use crate::engine::file_context::FileContext;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5706 — `__exit__` re-raising the provided exception --------------

pub(crate) fn check_exit_reraises_argument(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        if function.name.as_str() != "__exit__" {
            continue;
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
                    "Remove this \"raise\" statement and return \"False\" instead.",
                    raised.range(),
                    index,
                    source,
                ));
            }
        });
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5706_flags_exit_reraising_its_arguments() {
        let flagged = scan(concat!(
            "class C:\n",
            "    def __exit__(self, kind, value, trace):\n",
            "        cleanup(value)\n",
            "        raise value\n"
        ));
        assert_eq!(findings(&flagged, "python:S5706").len(), 1);
        let clean = concat!(
            "class C:\n",
            "    def __exit__(self, kind, value, trace):\n",
            "        cleanup(value)\n",
            "        return False\n"
        );
        assert!(findings(&scan(clean), "python:S5706").is_empty());
    }
}
