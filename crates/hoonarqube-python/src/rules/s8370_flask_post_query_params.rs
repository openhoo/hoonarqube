use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, expr_in, for_each_expr, function_scope, issue_at, keyword_value, scope_maps,
    stmt_exprs, string_literal_text, visit_scoped_stmts, visit_scoped_stmts_with_chain,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashMap;

const RULE_KEY: &str = "python:S8370";
const MESSAGE: &str =
    "Do not use query parameters with POST requests; use path parameters or request body instead.";
const SAFE_VERBS: [&str; 4] = ["GET", "HEAD", "OPTIONS", "TRACE"];

/// python:S8370 — a Flask route restricted to POST should take its data from
/// the request body or path parameters, not from `request.args`. The
/// reference check (`FlaskPostWithQueryParameterCheck`) fires on functions
/// decorated with a called `Flask.route`/`Blueprint.route` whose `methods`
/// keyword is a list literal containing the exact string `"POST"` and no
/// safe verb (`GET`/`HEAD`/`OPTIONS`/`TRACE`, case-insensitive); every
/// `request.args` attribute access anywhere inside the function — including
/// nested functions — anchors a finding. Routes without a `methods` list,
/// mixed POST+safe-verb routes, and non-Flask `request` objects stay
/// silent.
pub(crate) fn check_s8370_flask_post_query_params(
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
            if !is_post_route(function, scopes) {
                return;
            }
            flag_request_args(function, scopes, index, source, &mut issues);
        },
    );
    issues
}

/// Whether any decorator is a called `route` on a Flask app or blueprint
/// whose `methods` list contains POST and no safe verb.
fn is_post_route(
    function: &StmtFunctionDef,
    scopes: &[(bool, &HashMap<String, WebBinding>)],
) -> bool {
    let maps = scope_maps(scopes);
    function
        .decorator_list
        .iter()
        .any(|decorator| is_post_decorator(&decorator.expression, &maps))
}

fn is_post_decorator(expression: &Expr, scopes: &[&HashMap<String, WebBinding>]) -> bool {
    let Expr::Call(call) = expression else {
        return false;
    };
    if expr_in(&call.func, scopes) != WebBinding::FlaskRoute {
        return false;
    }
    methods_contains_post_only(call)
}

/// `containsPostButNoSafeVerbs`: the `methods` keyword must be a list
/// literal whose string elements include `"POST"` (exact case) and no safe
/// verb (case-insensitive); a missing or non-list `methods` argument is not
/// a POST-only route.
fn methods_contains_post_only(call: &ExprCall) -> bool {
    let Some(methods) = keyword_value(&call.arguments, "methods") else {
        return false;
    };
    let Expr::List(list) = methods else {
        return false;
    };
    let verbs: Vec<String> = list.elts.iter().filter_map(string_literal_text).collect();
    verbs.iter().any(|verb| verb == "POST")
        && verbs
            .iter()
            .all(|verb| !SAFE_VERBS.contains(&verb.to_uppercase().as_str()))
}

/// Flags every `request.args` attribute access inside the route function,
/// descending into nested definitions like the reference's recursive tree
/// search. The walk is seeded with the chain the function body sees so
/// `request` resolves through the same scopes as the route itself.
fn flag_request_args(
    function: &StmtFunctionDef,
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
    let mut chain: Vec<(bool, HashMap<String, WebBinding>)> = scopes
        .iter()
        .filter(|(is_class, _)| !*is_class)
        .map(|(_, map)| (false, (*map).clone()))
        .collect();
    chain.push((false, function_map));
    visit_scoped_stmts_with_chain(&function.body, chain, &mut |stmt, scopes| {
        let maps = scope_maps(scopes);
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if matches!(expr, Expr::Attribute(attribute)
                    if attribute.attr.as_str() == "args"
                        && expr_in(&attribute.value, &maps) == WebBinding::FlaskRequest)
                {
                    issues.push(issue_at(RULE_KEY, MESSAGE, expr.range(), index, source));
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8370")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8370_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `request.args` inside a POST-only
        // route anchors on the attribute expression.
        let ranges = found(concat!(
            "from flask import Flask, request\n",
            "app = Flask(__name__)\n",
            "\n",
            "@app.route('/resource', methods=['POST'])\n",
            "def update_text():\n",
            "    key = request.args.get('key')\n",
            "    data = request.get_data()\n",
            "    return 'Updated'\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(6, 10));
        assert_eq!(ranges[0].end, pos(6, 22));
    }

    #[test]
    fn s8370_accepts_the_sonar_compliant_example() {
        // Sonar's Compliant example: path parameters and the request body
        // replace query parameters.
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.route('/users/<user_id>', methods=['POST'])\n",
                "def update_user(user_id):\n",
                "    data = request.get_json()\n",
                "    return 'Updated'\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8370_ignores_mixed_and_safe_method_routes() {
        // A route mixing POST with a safe verb, a GET-only route, and a
        // route without a methods list all stay silent.
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "app = Flask(__name__)\n",
                "\n",
                "@app.route('/a', methods=['POST', 'GET'])\n",
                "def mixed():\n",
                "    return request.args.get('k')\n",
                "\n",
                "@app.route('/b', methods=['GET'])\n",
                "def safe():\n",
                "    return request.args.get('k')\n",
                "\n",
                "@app.route('/c')\n",
                "def defaulted():\n",
                "    return request.args.get('k')\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8370_flags_nested_and_blueprint_usage() {
        // `request.args` inside a nested function of a POST route flags, as
        // does access through a blueprint route; `flask.request` attribute
        // chains resolve too.
        let ranges = found(concat!(
            "import flask\n",
            "from flask import Blueprint\n",
            "bp = Blueprint('api', __name__)\n",
            "\n",
            "@bp.route('/x', methods=['POST', 'PUT'])\n",
            "def outer():\n",
            "    def inner():\n",
            "        return flask.request.args.get('k')\n",
            "    return inner()\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(8, 15));
        assert_eq!(ranges[0].end, pos(8, 33));
    }

    #[test]
    fn s8370_ignores_shadowed_request_names() {
        // A `request` parameter or local assignment is not the Flask proxy;
        // a non-list methods argument is not a POST-only route either.
        assert!(
            found(concat!(
                "from flask import Flask, request\n",
                "app = Flask(__name__)\n",
                "METHODS = ['POST']\n",
                "\n",
                "@app.route('/a', methods=['POST'])\n",
                "def shadowed(request):\n",
                "    return request.args.get('k')\n",
                "\n",
                "@app.route('/b', methods=METHODS)\n",
                "def indirect():\n",
                "    return request.args.get('k')\n",
            ))
            .is_empty()
        );
    }
}
