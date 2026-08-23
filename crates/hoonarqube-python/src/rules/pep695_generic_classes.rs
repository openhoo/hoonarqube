use crate::support::dotted_name;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6792 / S6794 / S6795 / S6796 — PEP 695 adoption ----------------------

pub(crate) fn check_pep695_generic_classes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            let generic_base = class.arguments.as_ref().is_some_and(|arguments| {
                arguments.args.iter().any(|base| {
                    matches!(base, Expr::Subscript(subscript)
                        if matches!(dotted_name(&subscript.value).as_deref(),
                            Some("Generic" | "typing.Generic")))
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
    });
    issues
}
