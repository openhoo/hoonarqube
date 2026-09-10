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
    let first_parameter_is_request = positional_parameters(&function.parameters)
        .first()
        .is_some_and(|parameter| parameter.name.as_str() == "request");
    first_parameter_is_request
        && returns_http_response(function, file_ctx)
        && !has_method_restriction(function, file_ctx)
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
