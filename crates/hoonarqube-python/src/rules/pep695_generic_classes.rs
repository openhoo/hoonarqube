use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6792 / S6794 / S6795 / S6796 — PEP 695 adoption ----------------------

pub(crate) fn check_pep695_generic_classes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::ClassDef(class) = stmt {
            let generic_base = class.arguments.as_ref().is_some_and(|arguments| {
                arguments.args.iter().any(|base| {
                    matches!(base, Expr::Subscript(subscript)
                        if dotted_name_in(&subscript.value, &["Generic", "typing.Generic"]))
                })
            });
            if generic_base {
                issues.push(issue_at(
                    "python:S6792",
                    "Use PEP 695 type parameters instead of inheriting Generic[...].",
                    class.name.range(),
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
    fn s6792_prefers_pep695_generic_classes() {
        let flagged = scan("class Box(Generic[T]):\n    pass\nclass Plain:\n    pass\n");
        assert_eq!(findings(&flagged, "python:S6792").len(), 1);
    }
}
