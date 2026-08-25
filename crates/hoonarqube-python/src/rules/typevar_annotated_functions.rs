use crate::engine::file_context::FileContext;
use crate::support::collect_typevar_names;
use crate::support::for_each_expr;
use crate::support::function_parameters;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typevar_annotated_functions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let typevars = collect_typevar_names(parsed.syntax().body.as_slice());
    if typevars.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt {
            let annotations = function_parameters(function)
                .iter()
                .filter_map(|parameter| parameter.parameter.annotation.as_deref())
                .chain(function.returns.as_deref())
                .collect::<Vec<_>>();
            let mut flagged = false;
            for annotation in annotations {
                for_each_expr(annotation, &mut |expr| {
                    if !flagged
                        && matches!(expr, Expr::Name(name)
                            if typevars.iter().any(|typevar| typevar == name.id.as_str()))
                    {
                        flagged = true;
                    }
                });
            }
            if flagged {
                issues.push(issue_at(
                    "python:S6796",
                    "Use PEP 695 type parameters instead of TypeVar hints.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6796_prefers_pep695_parameters_over_typevar_hints() {
        let flagged = scan(concat!(
            "T = TypeVar(\"T\")\n",
            "def identity(x: T) -> T:\n",
            "    return x\n",
            "def plain(x: int) -> int:\n",
            "    return x\n"
        ));
        assert_eq!(findings(&flagged, "python:S6796").len(), 1);
    }
}
