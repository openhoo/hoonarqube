use crate::support::binding_stmt_targets;
use crate::support::for_each_function_def;
use crate::support::for_each_stmt_in_scope;
use crate::support::function_all_parameters;
use crate::support::issue_at;
use crate::support::matches_snake_case;
use crate::support::push_local_name_issue;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

/// Parameters and locals of every function are python:S117; nested
/// definitions form their own scopes and are checked separately.
pub(crate) fn check_parameter_and_local_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _| {
            let mut seen = HashSet::new();
            for name in function_all_parameters(function) {
                if !seen.insert(name.as_str().to_string()) {
                    continue;
                }
                if !matches_snake_case(name.as_str()) {
                    issues.push(issue_at(
                        "python:S117",
                        &format!(
                            "Rename this parameter \"{name}\" to match the regular expression \
                             ^[_a-z][a-z0-9_]*$."
                        ),
                        name.range(),
                        index,
                        source,
                    ));
                }
            }
            for_each_stmt_in_scope(&function.body, &mut |stmt| {
                for target in binding_stmt_targets(stmt) {
                    if let Expr::Name(name) = target {
                        push_local_name_issue(
                            &mut issues,
                            &mut seen,
                            name.id.as_str(),
                            target.range(),
                            index,
                            source,
                        );
                    }
                }
                if let Stmt::Try(try_stmt) = stmt {
                    for handler in &try_stmt.handlers {
                        let ExceptHandler::ExceptHandler(inner) = handler;
                        if let Some(name) = &inner.name {
                            push_local_name_issue(
                                &mut issues,
                                &mut seen,
                                name.as_str(),
                                name.range(),
                                index,
                                source,
                            );
                        }
                    }
                }
            });
        },
    );
    issues
}
