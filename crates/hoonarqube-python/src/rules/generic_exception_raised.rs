use crate::support::for_each_function_def;
use crate::support::for_each_stmt_expr_in_scope;
use crate::support::for_each_stmt_in_scope;
use crate::support::function_all_parameters;
use crate::support::issue_at;
use crate::support::stmt_store_names;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

const RULE: &str = "python:S112";
const MESSAGE: &str = "Replace this generic exception class with a more specific one.";

/// `python:S112` — generic `Exception`/`BaseException` objects must not escape.
///
/// Mirrors the upstream rule's file-local cases: direct raises, locally bound
/// generic exception objects, and positional arguments that pass such objects
/// to a helper. Parameters and module-owned objects are deliberately excluded.
pub(crate) fn check_generic_exception_raised(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = check_scope(parsed.syntax().body.as_slice(), &[], false, index, source);
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _| {
            let parameters = function_all_parameters(function)
                .into_iter()
                .map(ruff_python_ast::Identifier::as_str)
                .collect::<Vec<_>>();
            issues.extend(check_scope(
                function.body.as_slice(),
                &parameters,
                true,
                index,
                source,
            ));
        },
    );
    issues
}

fn check_scope(
    body: &[Stmt],
    parameters: &[&str],
    is_function: bool,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut shadowed_builtins: HashSet<String> = parameters
        .iter()
        .filter(|name| is_generic_name(name))
        .map(|name| (*name).to_string())
        .collect();
    for_each_stmt_in_scope(body, &mut |stmt| {
        shadowed_builtins.extend(
            stmt_store_names(stmt)
                .into_iter()
                .filter(|name| is_generic_name(name)),
        );
    });

    let mut local_objects = HashSet::new();
    if is_function {
        for_each_stmt_in_scope(body, &mut |stmt| match stmt {
            Stmt::Assign(assign) if is_generic_object(&assign.value, &shadowed_builtins) => {
                for target in &assign.targets {
                    collect_name_targets(target, &mut local_objects);
                }
            }
            Stmt::AnnAssign(assign)
                if assign
                    .value
                    .as_deref()
                    .is_some_and(|value| is_generic_object(value, &shadowed_builtins)) =>
            {
                collect_name_targets(&assign.target, &mut local_objects);
            }
            _ => {}
        });
    }

    let mut issues = Vec::new();
    for_each_stmt_in_scope(body, &mut |stmt| {
        let Stmt::Raise(raised) = stmt else {
            return;
        };
        let Some(exception) = raised.exc.as_deref() else {
            return;
        };
        if is_generic_class_or_object(exception, &shadowed_builtins)
            || is_local_object_name(exception, &local_objects)
        {
            issues.push(issue_at(RULE, MESSAGE, exception.range(), index, source));
        }
    });

    for_each_stmt_expr_in_scope(body, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        for argument in &call.arguments.args {
            if is_generic_object(argument, &shadowed_builtins)
                || is_local_object_name(argument, &local_objects)
            {
                issues.push(issue_at(RULE, MESSAGE, argument.range(), index, source));
            }
        }
    });
    issues
}

fn is_generic_name(name: &str) -> bool {
    matches!(name, "Exception" | "BaseException")
}

fn is_generic_class(expr: &Expr, shadowed_builtins: &HashSet<String>) -> bool {
    match expr {
        Expr::Name(name) => {
            is_generic_name(name.id.as_str()) && !shadowed_builtins.contains(name.id.as_str())
        }
        Expr::Attribute(attribute) => {
            is_generic_name(attribute.attr.as_str())
                && matches!(attribute.value.as_ref(), Expr::Name(base) if base.id.as_str() == "builtins")
        }
        _ => false,
    }
}

fn is_generic_object(expr: &Expr, shadowed_builtins: &HashSet<String>) -> bool {
    matches!(expr, Expr::Call(call) if is_generic_class(&call.func, shadowed_builtins))
}

fn is_generic_class_or_object(expr: &Expr, shadowed_builtins: &HashSet<String>) -> bool {
    is_generic_class(expr, shadowed_builtins) || is_generic_object(expr, shadowed_builtins)
}

fn is_local_object_name(expr: &Expr, local_objects: &HashSet<String>) -> bool {
    matches!(expr, Expr::Name(name) if local_objects.contains(name.id.as_str()))
}

fn collect_name_targets(target: &Expr, names: &mut HashSet<String>) {
    match target {
        Expr::Name(name) => {
            names.insert(name.id.to_string());
        }
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_name_targets(element, names);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                collect_name_targets(element, names);
            }
        }
        Expr::Starred(starred) => collect_name_targets(&starred.value, names),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s112_flags_direct_generic_exception_raises() {
        let report = scan(
            "raise Exception()\nraise BaseException('stop')\nraise Exception\nraise BaseException\n",
        );
        assert_eq!(findings(&report, "python:S112").len(), 4);
    }

    #[test]
    fn s112_spares_bare_and_specific_exception_raises() {
        let report = scan(
            "class DomainError(Exception):\n    pass\n\ndef f():\n    try:\n        work()\n    except DomainError:\n        raise\n    raise DomainError('bad')\n",
        );
        assert!(findings(&report, "python:S112").is_empty());
    }

    #[test]
    fn s112_tracks_function_local_generic_exception_objects() {
        let report = scan(
            "def f(flag):\n    if flag:\n        problem = Exception('bad')\n        raise problem\n    other = BaseException()\n    handle(other)\n",
        );
        assert_eq!(findings(&report, "python:S112").len(), 2);
    }

    #[test]
    fn s112_spares_parameters_and_module_owned_exception_objects() {
        let report = scan(
            "global_problem = BaseException()\n\ndef f(problem: BaseException):\n    raise problem\n\ndef g():\n    raise global_problem\n",
        );
        assert!(findings(&report, "python:S112").is_empty());
    }

    #[test]
    fn s112_flags_generic_exception_objects_passed_positionally_only() {
        let report = scan(
            "handle(Exception())\nhandle(BaseException('stop'))\nhandle(problem=Exception())\n",
        );
        assert_eq!(findings(&report, "python:S112").len(), 2);
    }

    #[test]
    fn s112_respects_local_shadowing_of_builtin_exception_names() {
        let report = scan(
            "class LocalError:\n    pass\n\ndef f():\n    Exception = LocalError\n    raise Exception()\n",
        );
        assert!(findings(&report, "python:S112").is_empty());
    }

    #[test]
    fn s112_recognizes_explicit_builtins_qualification() {
        let report = scan("import builtins\nraise builtins.Exception('bad')\n");
        assert_eq!(findings(&report, "python:S112").len(), 1);
    }
}
