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
            if let Expr::Lambda(lambda) = expr {
                // A loop variable bound as a parameter is the rule's own
                // recommended fix, not a capture.
                let free_targets: Vec<String> = targets
                    .iter()
                    .filter(|target| {
                        !lambda
                            .parameters
                            .as_deref()
                            .is_some_and(|parameters| parameters_include(parameters, target))
                    })
                    .cloned()
                    .collect();
                if loads_any_name(&lambda.body, &free_targets) {
                    report_lambda_capture(&lambda.body, &free_targets, index, source, &mut issues);
                }
            }
        });
        for_each_stmt(&for_stmt.body, &mut |nested| {
            if let Stmt::FunctionDef(function) = nested {
                // A loop variable bound as a parameter is the rule's own
                // recommended fix, not a capture.
                let free_targets: Vec<String> = targets
                    .iter()
                    .filter(|target| !parameters_include(&function.parameters, target))
                    .cloned()
                    .collect();
                if !free_targets.is_empty() && stmts_load_any_name(&function.body, &free_targets) {
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
            }
        });
    }
    issues
}

fn report_lambda_capture(
    body: &Expr,
    targets: &[String],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut reported = false;
    for_each_expr(body, &mut |node| {
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

/// Whether `parameters` declares `name` as any parameter (positional,
/// keyword-only, `*args`, or `**kwargs`).
fn parameters_include(parameters: &ruff_python_ast::Parameters, name: &str) -> bool {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .any(|param| param.parameter.name.as_str() == name)
        || parameters
            .vararg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
        || parameters
            .kwarg
            .as_ref()
            .is_some_and(|param| param.name.as_str() == name)
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

    #[test]
    fn s1515_exempts_functions_taking_the_loop_variable_as_parameter() {
        // Issue #633: a parameter binding the loop variable is the rule's own
        // recommended fix, not a capture (Sonar reports 0 on this shape).
        let source = "def build(transforms):\n    final_transformer = None\n    for name in transforms:\n        def transform(field, alias, *, name, previous):\n            return previous(field, alias) + name\n        import functools\n        final_transformer = functools.partial(transform, name=name, previous=final_transformer)\n    return final_transformer\n";
        assert!(findings(&scan(source), "python:S1515").is_empty());
        // A sibling function that still closes over the loop variable stays
        // flagged while the parameterized one remains exempt.
        let flagged = "for item in items:\n    def helper(item=item):\n        return item\n    def capture():\n        return item\n";
        let flagged_report = scan(flagged);
        let found = findings(&flagged_report, "python:S1515");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
    }

    #[test]
    fn s1515_exempts_lambdas_taking_the_loop_variable_as_parameter() {
        // Sonar's documented compliant shape: the parameter shadows the
        // capture, so `lambda i=i: i` is not flagged.
        let source = "callbacks = []\nfor i in range(3):\n    callbacks.append(lambda i=i: i)\n";
        assert!(findings(&scan(source), "python:S1515").is_empty());
        // A lambda that still loads the loop variable from the enclosing scope
        // is flagged even when another parameter exists.
        let flagged =
            "callbacks = []\nfor i in range(3):\n    callbacks.append(lambda x=i: x + i)\n";
        let flagged_report = scan(flagged);
        let found = findings(&flagged_report, "python:S1515");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }
}
