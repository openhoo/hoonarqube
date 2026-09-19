use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, body_scopes, collect_target_names, expr_in, for_each_expr, for_each_stmt,
    for_each_stmt_in_scope, function_scope, issue_at, named_parameters, nth_argument_or_keyword,
    scope_maps, stmt_exprs, stmt_store_names, visit_scoped_stmts,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef, StmtReturn};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

const RULE_KEY: &str = "python:S6863";
const MESSAGE: &str = "Specify an explicit HTTP status code for this error handler.";

/// python:S6863 — Flask error handlers do not inherit the status code of the
/// error they handle: a handler registered with `@app.errorhandler(404)`
/// still answers 200 unless the response carries an explicit status. The
/// reference check (`FlaskErrorHandlerStatusCheck`) inspects every `return`
/// of a function decorated with `Flask.errorhandler`,
/// `Blueprint.errorhandler`, or `Blueprint.app_errorhandler` (call form
/// only): a bare `return`, a single non-call expression, and calls to
/// `jsonify`/`render_template`/`render_template_string` or to
/// `make_response`/`Response` without a `status` argument are findings.
/// `return a, b` tuples, names whose `status_code` attribute is assigned,
/// names bound once to a tuple of two or more elements, and unresolvable
/// names stay silent. Handlers registered via `register_error_handler()`
/// are not covered by the reference check and stay silent here too.
pub(crate) fn check_s6863_flask_error_handler_status(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scoped_stmts(
        file_ctx.module_body,
        file_ctx.web_bindings.module_scope(),
        &mut |stmt, scopes| {
            let Stmt::FunctionDef(function) = stmt else {
                return;
            };
            if !is_error_handler(function, scopes) {
                return;
            }
            check_handler_returns(function, file_ctx, scopes, index, source, &mut issues);
        },
    );
    issues
}

/// Whether any decorator is a called `errorhandler`/`app_errorhandler` on a
/// Flask application or blueprint instance.
fn is_error_handler(
    function: &StmtFunctionDef,
    scopes: &[(bool, &HashMap<String, WebBinding>)],
) -> bool {
    let maps = scope_maps(scopes);
    function.decorator_list.iter().any(|decorator| {
        matches!(&decorator.expression, Expr::Call(call)
            if expr_in(&call.func, &maps) == WebBinding::FlaskErrorHandler)
    })
}

fn check_handler_returns(
    function: &StmtFunctionDef,
    file_ctx: &FileContext,
    scopes: &[(bool, &HashMap<String, WebBinding>)],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let outer_maps: Vec<&HashMap<String, WebBinding>> = scopes
        .iter()
        .filter(|(is_class, _)| !*is_class)
        .map(|(_, map)| *map)
        .collect();
    let function_map = function_scope(function, &outer_maps);
    let body = body_scopes(scopes, &function_map);
    for_each_stmt_in_scope(&function.body, &mut |stmt| {
        let Stmt::Return(returned) = stmt else {
            return;
        };
        if return_is_problematic(returned, function, file_ctx, &body) {
            issues.push(issue_at(RULE_KEY, MESSAGE, returned.range(), index, source));
        }
    });
}

/// The reference's `ReturnStatementVisitor`: empty returns flag, two or more
/// returned expressions stay silent, and a single expression is classified
/// by shape.
fn return_is_problematic(
    returned: &StmtReturn,
    function: &StmtFunctionDef,
    file_ctx: &FileContext,
    body: &[&HashMap<String, WebBinding>],
) -> bool {
    let Some(value) = returned.value.as_deref() else {
        return true;
    };
    if let Expr::Tuple(tuple) = value {
        // `return a, b` is two returned expressions (silent); a parenthesized
        // or single-element tuple is one Tuple expression and flags.
        return tuple.parenthesized || tuple.elts.len() < 2;
    }
    match value {
        Expr::Name(name) => name_return_is_problematic(name.id.as_str(), function, file_ctx, body),
        Expr::Call(call) => is_problematic_flask_call(call, body),
        _ => true,
    }
}

/// A returned name is silent when its `status_code` attribute is assigned
/// anywhere in the handler, when it cannot be resolved to a single assigned
/// non-name value, or when that value is a tuple of at least two elements;
/// otherwise the resolved value is classified like a direct return.
fn name_return_is_problematic(
    name: &str,
    function: &StmtFunctionDef,
    file_ctx: &FileContext,
    body: &[&HashMap<String, WebBinding>],
) -> bool {
    if has_status_code_set(name, function) {
        return false;
    }
    let Some(value) = single_assigned_non_name_value(name, function, file_ctx) else {
        return false;
    };
    if let Expr::Tuple(tuple) = value
        && tuple.elts.len() >= 2
    {
        return false;
    }
    match value {
        Expr::Call(call) => is_problematic_flask_call(call, body),
        _ => true,
    }
}

/// `hasStatusCodeSet`: any `name.status_code` attribute expression inside an
/// assignment statement of the handler subtree (the reference consults the
/// symbol's usages, which span nested scopes).
fn has_status_code_set(name: &str, function: &StmtFunctionDef) -> bool {
    let mut found = false;
    for_each_stmt(&function.body, &mut |stmt| {
        if !matches!(stmt, Stmt::Assign(_)) {
            return;
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if matches!(expr, Expr::Attribute(attribute)
                    if attribute.attr.as_str() == "status_code"
                        && matches!(attribute.value.as_ref(), Expr::Name(base)
                            if base.id.as_str() == name))
                {
                    found = true;
                }
            });
        }
    });
    found
}

/// What the first binding event for a name in a scope is.
enum BindingOutcome<'a> {
    /// A plain `name = value` / `name: T = value` assignment.
    Value(&'a Expr),
    /// Any other binding (parameter, unpacking, import, def, walrus, ...).
    Other,
    /// The name is never bound in this scope.
    Unbound,
}

/// The reference's `singleAssignedNonNameValue`: resolves a name through
/// single plain assignments, chasing name-to-name aliases, and fails on
/// parameters, unpacking, or any other binding kind.
fn single_assigned_non_name_value<'a>(
    name: &str,
    function: &'a StmtFunctionDef,
    file_ctx: &'a FileContext,
) -> Option<&'a Expr> {
    let mut visited = HashSet::new();
    let mut current = name.to_string();
    loop {
        if !visited.insert(current.clone()) || is_parameter(function, &current) {
            return None;
        }
        let outcome = match first_binding(&function.body, &current) {
            BindingOutcome::Unbound => first_binding(file_ctx.module_body, &current),
            outcome => outcome,
        };
        match outcome {
            BindingOutcome::Value(Expr::Name(alias)) => {
                current = alias.id.as_str().to_string();
            }
            BindingOutcome::Value(value) => return Some(value),
            BindingOutcome::Other | BindingOutcome::Unbound => return None,
        }
    }
}

/// Whether `name` is one of the function's parameters.
fn is_parameter(function: &StmtFunctionDef, name: &str) -> bool {
    named_parameters(&function.parameters)
        .iter()
        .any(|parameter| parameter.parameter.name.as_str() == name)
        || [
            function.parameters.vararg.as_deref(),
            function.parameters.kwarg.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|parameter| parameter.name.as_str() == name)
}

/// The first binding event for `name` in the scope's own statements
/// (nested `def`/`class` bodies excluded).
fn first_binding<'a>(stmts: &'a [Stmt], name: &str) -> BindingOutcome<'a> {
    for stmt in stmts {
        // Walrus targets bind at evaluation time, ahead of the statement's
        // own binding.
        if stmt_binds_via_walrus(stmt, name) {
            return BindingOutcome::Other;
        }
        match statement_binding(stmt, name) {
            BindingOutcome::Unbound => {}
            outcome => return outcome,
        }
        if !matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            for body in crate::support::child_bodies(stmt) {
                match first_binding(body, name) {
                    BindingOutcome::Unbound => {}
                    outcome => return outcome,
                }
            }
        }
    }
    BindingOutcome::Unbound
}

/// Whether any expression in `stmt` binds `name` through a walrus target.
fn stmt_binds_via_walrus(stmt: &Stmt, name: &str) -> bool {
    stmt_exprs(stmt).iter().any(|expr| {
        let mut walrus = false;
        for_each_expr(expr, &mut |expr| {
            if matches!(expr, Expr::Named(named)
                if target_binds_name(&named.target, name))
            {
                walrus = true;
            }
        });
        walrus
    })
}

/// The binding a statement performs on `name`, if any.
fn statement_binding<'a>(stmt: &'a Stmt, name: &str) -> BindingOutcome<'a> {
    match stmt {
        Stmt::Assign(assign) => assign_binding(assign, name),
        Stmt::AnnAssign(assign) => {
            if !target_binds_name(&assign.target, name) {
                return BindingOutcome::Unbound;
            }
            match assign.value.as_deref() {
                Some(value) => BindingOutcome::Value(value),
                None => BindingOutcome::Other,
            }
        }
        _ => {
            if stmt_store_names(stmt).iter().any(|bound| bound == name) {
                BindingOutcome::Other
            } else {
                BindingOutcome::Unbound
            }
        }
    }
}

/// The binding a `Stmt::Assign` performs on `name`: a plain `name = value`
/// target yields the value, any other binding target is `Other`.
fn assign_binding<'a>(assign: &'a ruff_python_ast::StmtAssign, name: &str) -> BindingOutcome<'a> {
    for target in &assign.targets {
        if matches!(target, Expr::Name(target_name) if target_name.id.as_str() == name) {
            return BindingOutcome::Value(&assign.value);
        }
        if target_binds_name(target, name) {
            return BindingOutcome::Other;
        }
    }
    BindingOutcome::Unbound
}

/// Whether an assignment target binds `name` (plain name or inside a
/// tuple/list/starred unpacking).
fn target_binds_name(target: &Expr, name: &str) -> bool {
    let mut names = Vec::new();
    collect_target_names(target, &mut names);
    names.iter().any(|bound| bound == name)
}

/// `isProblematicFlaskFunction`: `jsonify`/`render_template`/
/// `render_template_string` always flag; `make_response`/`Response` flag
/// unless a `status` argument (keyword or second positional) is given.
fn is_problematic_flask_call(call: &ExprCall, scopes: &[&HashMap<String, WebBinding>]) -> bool {
    match expr_in(&call.func, scopes) {
        WebBinding::FlaskJsonify
        | WebBinding::FlaskRenderTemplate
        | WebBinding::FlaskRenderTemplateString => true,
        WebBinding::FlaskMakeResponse | WebBinding::FlaskResponseClass => {
            nth_argument_or_keyword(&call.arguments, 1, "status").is_none()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S6863")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s6863_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: template and JSON responses without
        // an explicit status code anchor on the return statement.
        let ranges = found(concat!(
            "from flask import Flask, render_template, jsonify\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def page_not_found(e):\n",
            "    return render_template('404.html')\n",
            "\n",
            "@app.errorhandler(500)\n",
            "def internal_error(e):\n",
            "    return jsonify(error=\"Internal server error\")\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[0].end, pos(6, 38));
        assert_eq!(ranges[1].start, pos(10, 4));
        assert_eq!(ranges[1].end, pos(10, 49));
    }

    #[test]
    fn s6863_accepts_the_sonar_compliant_examples() {
        // Sonar's Compliant examples: the status code rides in the return
        // tuple, so no finding is raised.
        assert!(
            found(concat!(
                "from flask import Flask, render_template, jsonify\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.errorhandler(404)\n",
                "def page_not_found(e):\n",
                "    return render_template('404.html'), 404\n",
                "\n",
                "@app.errorhandler(500)\n",
                "def internal_error(e):\n",
                "    return jsonify(error=\"Internal server error\"), 500\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s6863_ignores_register_error_handler_like_the_reference() {
        // The reference only inspects decorated functions; a handler passed
        // to register_error_handler() stays silent even when its return has
        // no status code.
        assert!(
            found(concat!(
                "from flask import Flask\n",
                "app = Flask(__name__)\n",
                "\n",
                "def handle_bad_request(e):\n",
                "    return 'Bad request!'\n",
                "\n",
                "app.register_error_handler(400, handle_bad_request)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s6863_flags_bare_and_literal_returns_on_blueprints() {
        // Bare returns and plain values flag; blueprint errorhandler and
        // app_errorhandler decorators count the same as the app's.
        let ranges = found(concat!(
            "from flask import Blueprint\n",
            "bp = Blueprint('api', __name__)\n",
            "\n",
            "@bp.errorhandler(404)\n",
            "def missing(e):\n",
            "    return\n",
            "\n",
            "@bp.app_errorhandler(400)\n",
            "def bad(e):\n",
            "    return 'Bad request!'\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[1].start, pos(10, 4));
    }

    #[test]
    fn s6863_response_helpers_respect_the_status_argument() {
        // make_response/Response calls flag only without a status argument;
        // a name whose status_code attribute is assigned stays silent, as do
        // names bound to a tuple and unresolvable names.
        let ranges = found(concat!(
            "from flask import Flask, make_response, Response\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def flagged(e):\n",
            "    return make_response('oops')\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def with_status(e):\n",
            "    return make_response('oops', status=404)\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def attribute(e):\n",
            "    resp = make_response('oops')\n",
            "    resp.status_code = 404\n",
            "    return resp\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def assigned_tuple(e):\n",
            "    pair = ('oops', 404)\n",
            "    return pair\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def passthrough(e):\n",
            "    return e\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[0].end, pos(6, 32));
    }

    #[test]
    fn s6863_ignores_other_calls_and_non_flask_apps() {
        // Calls that are not the Flask response helpers stay silent, and an
        // errorhandler decorator on a non-Flask object is not a finding.
        assert!(
            found(concat!(
                "from flask import Flask\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.errorhandler(404)\n",
                "def delegated(e):\n",
                "    return build_response(e)\n",
                "\n",
                "class App:\n",
                "    def errorhandler(self, code):\n",
                "        return lambda f: f\n",
                "other = App()\n",
                "\n",
                "@other.errorhandler(404)\n",
                "def not_flask(e):\n",
                "    return 'oops'\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s6863_flags_parenthesized_tuple_like_the_reference() {
        // `return (body, 404)` is a single Tuple expression in the
        // reference's grammar and flags, unlike the two-expression
        // `return body, 404` form.
        let ranges = found(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.errorhandler(404)\n",
            "def packed(e):\n",
            "    return ('oops', 404)\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(6, 4));
    }
}
