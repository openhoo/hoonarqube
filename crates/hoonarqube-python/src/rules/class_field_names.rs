use crate::engine::file_context::FileContext;
use crate::support::binding_target_names;
use crate::support::issue_at;
use crate::support::matches_field_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Fields assigned directly in a class body are python:S116.
pub(crate) fn check_class_field_names(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        for member in &class.body {
            let targets: Vec<&Expr> = match member {
                Stmt::Assign(assign) => assign.targets.iter().collect(),
                Stmt::AnnAssign(assignment) => vec![&*assignment.target],
                _ => continue,
            };
            for target in targets {
                for target_name in binding_target_names(target) {
                    let Expr::Name(name) = target_name else {
                        continue;
                    };
                    if !matches_field_name(name.id.as_str()) {
                        issues.push(issue_at(
                            "python:S116",
                            &format!(
                                "Rename this field \"{}\" to match the regular expression \
                                 ^[_a-z][_a-z0-9]*$.",
                                name.id
                            ),
                            target_name.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
        }
    }
    issues
}
