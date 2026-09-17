use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::positional_parameters;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3752 — HTTP routes restrict allowed methods ---------------------------

pub(crate) fn check_s3752_route_methods(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let wildcard_method = called_name(&call.func) == Some("add_route")
            && call
                .arguments
                .args
                .first()
                .and_then(string_literal_text)
                .is_some_and(|method| method == "*");
        let kitchen_sink = matches!(called_name(&call.func), Some("route" | "add_url_rule"))
            && keyword_value(&call.arguments, "methods").is_some_and(|methods| match methods {
                Expr::List(list) => list.elts.len() >= 5,
                _ => false,
            });
        if wildcard_method || kitchen_sink {
            issues.push(issue_at(
                "python:S3752",
                "Restrict this HTTP route to the methods it actually supports.",
                call.range(),
                index,
                source,
            ));
        }
    }
    for function in &file_ctx.functions {
        if is_unrestricted_django_view(function, file_ctx) {
            issues.push(issue_at(
                "python:S3752",
                "Restrict this HTTP route to the methods it actually supports.",
                function.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn is_unrestricted_django_view(function: &StmtFunctionDef, file_ctx: &FileContext) -> bool {
    // The reference's isDjangoView is project-level URLconf registration;
    // approximated per file by `path()`/`re_path()` view arguments and by
    // the request-param + response-producing contract, including one-level
    // delegation to another view-like function in the same file.
    let registered = crate::support::django_view_names(file_ctx.module_body)
        .contains(function.name.as_str())
        || path_call_registers(file_ctx, function.name.as_str());
    let first_parameter_is_request = positional_parameters(&function.parameters)
        .first()
        .is_some_and(|parameter| parameter.name.as_str() == "request");
    (registered || (first_parameter_is_request && produces_response(function, file_ctx)))
        && !has_method_restriction(function, file_ctx)
        && !has_non_django_decorator(function, file_ctx)
        && !has_request_method_check(function)
}

/// Whether `name` appears as the view argument of a `path()`/`re_path()`
/// call in this file (the reference's DjangoViewsVisitor registration).
fn path_call_registers(file_ctx: &FileContext, name: &str) -> bool {
    file_ctx.calls.iter().any(|call| {
        let is_route = matches!(
            crate::support::dotted_name(&call.func).as_deref(),
            Some("path" | "re_path" | "django.urls.path" | "django.urls.re_path"
                | "django.urls.conf.path" | "django.urls.conf.re_path"
                | "urls.path" | "urls.re_path")
        ) || matches!(called_name(&call.func), Some("path" | "re_path"));
        if !is_route {
            return false;
        }
        call.arguments
            .args
            .get(1)
            .is_some_and(|arg| matches!(arg, Expr::Name(n) if n.id.as_str() == name))
            || call.arguments.keywords.iter().any(|keyword| {
                keyword.arg.as_deref() == Some("view")
                    && matches!(&keyword.value, Expr::Name(n) if n.id.as_str() == name)
            })
    })
}

/// Whether the function's return values produce an HTTP response, directly
/// (`HttpResponse(...)`, `render(...)`) or by delegating to another function
/// in the same file that does.
fn produces_response(function: &StmtFunctionDef, file_ctx: &FileContext) -> bool {
    if returns_http_response(function, file_ctx) {
        return true;
    }
    let mut delegates = Vec::new();
    for_each_stmt_in_scope(&function.body, &mut |statement| {
        let Stmt::Return(return_stmt) = statement else {
            return;
        };
        if let Some(Expr::Call(call)) = return_stmt.value.as_deref()
            && let Some(name) = called_name(&call.func)
        {
            delegates.push(name.to_string());
        }
    });
    delegates.iter().any(|name| {
        file_ctx
            .functions
            .iter()
            .any(|other| other.name.as_str() == name && returns_http_response(other, file_ctx))
    })
}

/// The reference's hasRequestMethodCheck: a `request.method` comparison or
/// membership test inside an `if` condition restricts the view.
fn has_request_method_check(function: &StmtFunctionDef) -> bool {
    let mut found = false;
    for_each_stmt_in_scope(&function.body, &mut |statement| {
        let Stmt::If(if_stmt) = statement else {
            return;
        };
        crate::support::for_each_expr(&if_stmt.test, &mut |expr| {
            if let Expr::Attribute(attribute) = expr
                && attribute.attr.as_str() == "method"
                && matches!(attribute.value.as_ref(), Expr::Name(n) if n.id.as_str() == "request")
            {
                found = true;
            }
        });
    });
    found
}

fn returns_http_response(function: &StmtFunctionDef, file_ctx: &FileContext) -> bool {
    let mut found = false;
    for_each_stmt_in_scope(&function.body, &mut |statement| {
        if found {
            return;
        }
        let Stmt::Return(return_stmt) = statement else {
            return;
        };
        let Some(Expr::Call(call)) = return_stmt.value.as_deref() else {
            return;
        };
        found = file_ctx.known_bindings.resolve_call(call) == KnownBinding::DjangoHttpResponse;
    });
    found
}

/// The reference's hasNonDjangoDecorator: a decorator that does not resolve
/// to a `django.*` import exempts the view (custom decorators may restrict).
fn has_non_django_decorator(function: &StmtFunctionDef, file_ctx: &FileContext) -> bool {
    function.decorator_list.iter().any(|decorator| {
        let expression = &decorator.expression;
        let path = match expression {
            Expr::Call(call) => crate::support::dotted_name(&call.func),
            other => crate::support::dotted_name(other),
        };
        match path {
            Some(path) => !path.starts_with("django") && !path.contains("require_"),
            // Bare names imported from django.* are django decorators; other
            // bare names are treated as non-django.
            None => {
                let name = match expression {
                    Expr::Call(call) => called_name(&call.func),
                    other => called_name(other),
                };
                !name.is_some_and(|name| is_django_import(file_ctx, name))
            }
        }
    })
}

/// Whether `name` was imported from a `django.*` module.
fn is_django_import(file_ctx: &FileContext, name: &str) -> bool {
    file_ctx.imports.iter().any(|import| {
        let crate::engine::file_context::AnyImport::From(from) = import else {
            return false;
        };
        from.module
            .as_deref()
            .is_some_and(|module| module.starts_with("django"))
            && from.names.iter().any(|alias| {
                alias.asname.as_deref().unwrap_or(alias.name.as_str()) == name
            })
    })
}

fn has_method_restriction(function: &StmtFunctionDef, file_ctx: &FileContext) -> bool {
    function.decorator_list.iter().any(|decorator| {
        let expression = &decorator.expression;
        match expression {
            Expr::Call(call) => {
                file_ctx.known_bindings.resolve_call(call) == KnownBinding::DjangoMethodRestriction
            }
            _ => {
                file_ctx.known_bindings.resolve_expr_identity(expression)
                    == KnownBinding::DjangoMethodRestriction
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3752_recognizes_django_views_by_contract() {
        let attack = scan(
            "from django.http import HttpResponse\n\n\
             def view(request):\n    return HttpResponse(\"...\")\n",
        );
        assert_eq!(findings(&attack, "python:S3752").len(), 1);

        let safe = scan(
            "from django.http import HttpResponse\n\
             from django.views.decorators.http import require_http_methods\n\n\
             @require_http_methods([\"POST\"])\n\
             def view(request):\n    return HttpResponse(\"...\")\n",
        );
        assert!(findings(&safe, "python:S3752").is_empty());
    }

    #[test]
    fn s3752_does_not_guess_callers_defined_views() {
        let lookalike = scan(
            "class HttpResponse:\n    pass\n\n\
             def view(request):\n    return HttpResponse()\n",
        );
        assert!(findings(&lookalike, "python:S3752").is_empty());
    }
}
