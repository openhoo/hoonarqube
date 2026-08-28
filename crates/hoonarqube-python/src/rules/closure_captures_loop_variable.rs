use crate::engine::file_context::FileContext;
use crate::support::collect_target_names;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::loads_any_name;
use crate::support::stmts_load_any_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1515 — closures capturing loop variables --------------------------

pub(crate) fn check_closure_captures_loop_variable(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = stmt else { continue };
        let mut targets = Vec::new();
        collect_target_names(&for_stmt.target, &mut targets);
        if targets.is_empty() {
            continue;
        }
        for_each_stmt_expr(&for_stmt.body, &mut |expr| {
            if let Expr::Lambda(lambda) = expr
                && loads_any_name(&lambda.body, &targets)
            {
                let mut reported = false;
                for_each_expr(&lambda.body, &mut |node| {
                    if reported {
                        return;
                    }
                    if let Expr::Name(name) = node
                        && targets.iter().any(|target| target == name.id.as_str())
                    {
                        let variable = name.id.as_str();
                        issues.push(issue_at(
                            "python:S1515",
                            &format!(
                                "Add a parameter to the parent lambda function and use variable \
                                 \"{variable}\" as its default value; The value of \"{variable}\" \
                                 might change at the next loop iteration."
                            ),
                            name.range(),
                            index,
                            source,
                        ));
                        reported = true;
                    }
                });
            }
        });
        for_each_stmt(&for_stmt.body, &mut |nested| {
            if let Stmt::FunctionDef(function) = nested
                && stmts_load_any_name(&function.body, &targets)
            {
                issues.push(issue_at(
                    "python:S1515",
                    &format!(
                        "Add a parameter to function \"{}\" and use a captured loop variable as \
                         its default value; The value might change at the next loop iteration.",
                        function.name
                    ),
                    function.name.range(),
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
    fn s1515_flags_closures_capturing_loop_variables() {
        let flagged = scan("callbacks = []\nfor i in range(3):\n    callbacks.append(lambda: i)\n");
        let found = findings(&flagged, "python:S1515");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        let clean = "callbacks = []\nfor i in range(3):\n    callbacks.append(lambda v: v)\n";
        assert!(findings(&scan(clean), "python:S1515").is_empty());
    }
}
