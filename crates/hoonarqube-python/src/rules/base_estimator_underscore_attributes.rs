use crate::support::class_base_paths;
use crate::support::for_each_method;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_self_attribute;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_base_estimator_underscore_attributes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |class, function| {
        let estimator = class_base_paths(class)
            .iter()
            .any(|base| base.contains("BaseEstimator"));
        if !estimator || function.name.as_str() != "__init__" {
            return;
        }
        for_each_stmt_in_scope(function.body.as_slice(), &mut |stmt| {
            let targets: Vec<&Expr> = match stmt {
                Stmt::Assign(assign) => assign.targets.iter().collect(),
                Stmt::AnnAssign(assign) => vec![&assign.target],
                _ => Vec::new(),
            };
            for target in targets {
                if is_self_attribute(target, |attr| attr.ends_with('_')) {
                    issues.push(issue_at(
                        "python:S6974",
                        "Trailing-underscore attribute names are reserved for fitted state.",
                        target.range(),
                        index,
                        source,
                    ));
                }
            }
        });
    });
    issues
}
