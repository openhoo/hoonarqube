use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::{
    collect_target_names, for_each_stmt_expr_in_scope, for_each_stmt_in_scope, has_decorator,
    positional_parameters, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_infinite_recursion(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt {
            let receiver = method_receiver(function, &file_ctx.classes);
            if straight_line_self_call(function, receiver) {
                issues.push(issue_at(
                    "python:S2190",
                    "Add a way to break out of this function's recursion.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

fn straight_line_self_call(function: &StmtFunctionDef, receiver: Option<&str>) -> bool {
    let name = function.name.as_str();
    let direct_name_is_bound = !name_is_shadowed(function, name);
    let receiver_rebound = receiver.is_some_and(|name| body_rebinds_name(function, name));
    for stmt in &function.body {
        match stmt {
            Stmt::Expr(expr_stmt) => {
                if is_self_call(
                    &expr_stmt.value,
                    name,
                    direct_name_is_bound,
                    receiver,
                    !receiver_rebound,
                ) {
                    return true;
                }
            }
            Stmt::Return(return_stmt) => {
                if let Some(value) = return_stmt.value.as_deref()
                    && is_self_call(
                        value,
                        name,
                        direct_name_is_bound,
                        receiver,
                        !receiver_rebound,
                    )
                {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}
/// A recursive target is either an unqualified reference to the function's
/// lexical name or a method call through that method's first positional
/// receiver.  Attribute tails alone are insufficient: `super().run()` and
/// `other.run()` must not be treated as calls back into `run`.
fn is_self_call(
    expr: &Expr,
    name: &str,
    direct_name_is_bound: bool,
    receiver: Option<&str>,
    receiver_is_bound: bool,
) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    match call.func.as_ref() {
        Expr::Name(callee) => direct_name_is_bound && callee.id.as_str() == name,
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == name
                && receiver_is_bound
                && receiver.is_some_and(|receiver| {
                    matches!(
                        attribute.value.as_ref(),
                        Expr::Name(value) if value.id.as_str() == receiver
                    )
                })
        }
        _ => false,
    }
}

/// Finds a method's first positional binding only when the function is
/// directly in an enclosing class body.  Nested functions are not methods,
/// and static methods do not receive an implicit receiver.
fn method_receiver<'a>(
    function: &'a StmtFunctionDef,
    classes: &[&ruff_python_ast::StmtClassDef],
) -> Option<&'a str> {
    if has_decorator(function, "staticmethod") {
        return None;
    }
    let is_method = classes.iter().copied().any(|class| {
        let mut found = false;
        for_each_stmt_in_scope(class.body.as_slice(), &mut |statement| {
            if let Stmt::FunctionDef(candidate) = statement
                && candidate.range() == function.range()
            {
                found = true;
            }
        });
        found
    });
    is_method
        .then(|| positional_parameters(&function.parameters).first().copied())
        .flatten()
        .map(|parameter| parameter.name.as_str())
}

/// Any parameter or local binding with the function's name prevents proving
/// that an unqualified call resolves back to this function.
fn name_is_shadowed(function: &StmtFunctionDef, name: &str) -> bool {
    positional_parameters(&function.parameters)
        .iter()
        .any(|parameter| parameter.name.as_str() == name)
        || function
            .parameters
            .vararg
            .as_ref()
            .is_some_and(|parameter| parameter.name.as_str() == name)
        || function
            .parameters
            .kwarg
            .as_ref()
            .is_some_and(|parameter| parameter.name.as_str() == name)
        || body_rebinds_name(function, name)
}

/// Python local bindings include assignments nested in control-flow suites,
/// imports, definitions, deletes, and named expressions.  The traversal
/// intentionally skips nested function/class scopes.
fn body_rebinds_name(function: &StmtFunctionDef, name: &str) -> bool {
    let mut rebound = false;
    for_each_stmt_in_scope(&function.body, &mut |statement| {
        rebound |= stmt_store_names(statement)
            .iter()
            .any(|bound| bound == name);
    });
    for_each_stmt_expr_in_scope(&function.body, &mut |expression| {
        if let Expr::Named(named) = expression {
            let mut names = Vec::new();
            collect_target_names(&named.target, &mut names);
            rebound |= names.iter().any(|bound| bound == name);
        }
    });
    rebound
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2190_requires_a_proven_recursive_target() {
        let source = concat!(
            "def spin():\n",
            "    return spin()\n",
            "\n",
            "class Base:\n",
            "    def run(self):\n",
            "        return self.run()\n",
            "\n",
            "class Derived(Base):\n",
            "    def run(self):\n",
            "        return super().run()\n",
            "\n",
            "class Delegating:\n",
            "    def run(self, other):\n",
            "        return other.run()\n",
            "\n",
            "def shadowed(shadowed):\n",
            "    return shadowed()\n",
        );
        assert_eq!(findings(&scan(source), "python:S2190").len(), 2);
    }
}
