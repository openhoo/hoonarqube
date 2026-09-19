use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, body_scopes, collect_target_names, expr_in, flow_location, for_each_expr,
    for_each_stmt_in_scope, function_scope, issue_at, keyword_value, scope_maps, stmt_exprs,
    stmt_store_names, string_literal_text, visit_scoped_stmts,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef, StmtReturn};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashMap;

const RULE_KEY: &str = "python:S8400";
const MESSAGE: &str = "Return an empty body for this endpoint returning 204 status.";
const SECONDARY_MESSAGE: &str = "Response is assigned here";

/// python:S8400 — RFC 7231 forbids a body on a `204` response, but `FastAPI`
/// serializes the endpoint's return value, so a `status_code=204` endpoint
/// that returns content (or lets the default `null` body through) violates
/// the contract. The reference check (`HttpNoContentNonEmptyBodyCheck`)
/// inspects functions decorated with a called `FastAPI.get`/`post`/`put`/
/// `delete`/`patch`/`options`/`head`/`trace` carrying `status_code=204`:
/// every `return` outside nested functions must produce an empty body —
/// bare `return`, `None`, or a `fastapi.Response` instance whose call does
/// not pass a non-204 `status_code` or a non-empty `content`. Anything else
/// anchors a finding on the return statement; an invalid `Response(...)`
/// call assigned to the returned name adds a "Response is assigned here"
/// secondary location.
pub(crate) fn check_s8400_fastapi_no_content_body(
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
            if !is_no_content_endpoint(function, scopes) {
                return;
            }
            check_endpoint_returns(function, file_ctx, scopes, index, source, &mut issues);
        },
    );
    issues
}

/// Whether any decorator is a called `FastAPI` route method with
/// `status_code=204`.
fn is_no_content_endpoint(
    function: &StmtFunctionDef,
    scopes: &[(bool, &HashMap<String, WebBinding>)],
) -> bool {
    let maps = scope_maps(scopes);
    function.decorator_list.iter().any(|decorator| {
        let Expr::Call(call) = &decorator.expression else {
            return false;
        };
        if expr_in(&call.func, &maps) != WebBinding::FastApiRouteMethod {
            return false;
        }
        keyword_value(&call.arguments, "status_code").is_some_and(is_no_content_status_value)
    })
}

/// The literal `204` (the reference compares the numeric literal's token).
fn is_no_content_status_value(expr: &Expr) -> bool {
    matches!(expr, Expr::NumberLiteral(number)
        if matches!(&number.value, ruff_python_ast::Number::Int(value)
            if value.as_i64() == Some(204)))
}

fn check_endpoint_returns(
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
        let validation = validate_return(returned, function, file_ctx.module_body, &body);
        if validation.valid {
            return;
        }
        let mut issue = issue_at(RULE_KEY, MESSAGE, returned.range(), index, source);
        if !validation.secondaries.is_empty() {
            issue = issue.with_flow(
                validation
                    .secondaries
                    .iter()
                    .map(|range| flow_location(SECONDARY_MESSAGE, *range, index, source))
                    .collect(),
            );
        }
        issues.push(issue);
    });
}

/// The reference's `ValidationResult`: whether the return produces an empty
/// body, plus the invalid `Response(...)` call sites behind a returned name.
struct Validation {
    valid: bool,
    secondaries: Vec<TextRange>,
}

impl Validation {
    fn valid() -> Self {
        Self {
            valid: true,
            secondaries: Vec::new(),
        }
    }

    fn invalid(secondaries: Vec<TextRange>) -> Self {
        Self {
            valid: false,
            secondaries,
        }
    }
}

/// `isValidReturnStatement`: bare `return` and `return None` are valid; a
/// single returned expression must be a `fastapi.Response` instance whose
/// construction is not invalid; anything else is a finding.
fn validate_return(
    returned: &StmtReturn,
    function: &StmtFunctionDef,
    module_body: &[Stmt],
    body: &[&HashMap<String, WebBinding>],
) -> Validation {
    let Some(value) = returned.value.as_deref() else {
        return Validation::valid();
    };
    if let Expr::Tuple(tuple) = value
        && !tuple.parenthesized
        && tuple.elts.len() >= 2
    {
        // `return a, b` is more than one expression — never an empty body.
        return Validation::invalid(Vec::new());
    }
    if matches!(value, Expr::NoneLiteral(_)) {
        return Validation::valid();
    }
    validate_response_object(value, function, module_body, body)
}

/// `isValidResponseObject`: a `Response(...)` call is checked directly; a
/// name resolves to its assigned call values, each checked the same way
/// (invalid sites become secondary locations); anything that is not a
/// `fastapi.Response` instance is invalid.
fn validate_response_object(
    value: &Expr,
    function: &StmtFunctionDef,
    module_body: &[Stmt],
    body: &[&HashMap<String, WebBinding>],
) -> Validation {
    match value {
        Expr::Call(call) => {
            if expr_in(&call.func, body) != WebBinding::FastApiResponseClass {
                return Validation::invalid(Vec::new());
            }
            if is_invalid_response_call(call) {
                Validation::invalid(Vec::new())
            } else {
                Validation::valid()
            }
        }
        Expr::Name(name) => validate_named_response(name, function, module_body, body),
        _ => Validation::invalid(Vec::new()),
    }
}

/// `isValidResponseObject` for a returned name: resolves to its assigned
/// call values, each checked like a direct `Response(...)` call (invalid
/// sites become secondary locations). A parameter annotated as a Response
/// subclass counts as a Response instance; anything unresolvable is invalid.
fn validate_named_response(
    name: &ruff_python_ast::ExprName,
    function: &StmtFunctionDef,
    module_body: &[Stmt],
    body: &[&HashMap<String, WebBinding>],
) -> Validation {
    let calls = assigned_call_values(name.id.as_str(), function, module_body);
    if calls.is_empty() {
        if annotated_response_parameter(name.id.as_str(), function, body) {
            return Validation::valid();
        }
        return Validation::invalid(Vec::new());
    }
    let mut secondaries = Vec::new();
    for call in calls {
        if expr_in(&call.func, body) != WebBinding::FastApiResponseClass {
            return Validation::invalid(Vec::new());
        }
        if is_invalid_response_call(call) {
            secondaries.push(call.range());
        }
    }
    if secondaries.is_empty() {
        Validation::valid()
    } else {
        Validation::invalid(secondaries)
    }
}

/// `isInvalidResponseCall`: a `status_code` argument that is not the
/// literal 204, or a `content` argument that is not an empty string
/// literal, makes the response carry a body.
fn is_invalid_response_call(call: &ExprCall) -> bool {
    if let Some(status) = keyword_value(&call.arguments, "status_code")
        && !is_no_content_status_value(status)
    {
        return true;
    }
    if let Some(content) = keyword_value(&call.arguments, "content") {
        return string_literal_text(content).is_none_or(|text| !text.is_empty());
    }
    false
}

/// Whether `name` is a parameter annotated with a `*Response` class — the
/// reference's `isObjectInstanceOf(fastapi.Response)` accepts annotated
/// parameters as Response instances.
fn annotated_response_parameter(
    name: &str,
    function: &StmtFunctionDef,
    body: &[&HashMap<String, WebBinding>],
) -> bool {
    let parameters = crate::support::named_parameters(&function.parameters)
        .into_iter()
        .map(|with_default| &with_default.parameter)
        .chain(
            [
                function.parameters.vararg.as_deref(),
                function.parameters.kwarg.as_deref(),
            ]
            .into_iter()
            .flatten(),
        );
    parameters
        .filter(|parameter| parameter.name.as_str() == name)
        .filter_map(|parameter| parameter.annotation.as_deref())
        .any(|annotation| expr_in(annotation, body) == WebBinding::FastApiResponseClass)
}

/// Call expressions assigned to `name` — the reference's
/// `valuesAtLocation` approximation. Plain `name = <call>` assignments in
/// the function's own statements (nested scopes excluded) contribute; when
/// the name is never bound there, the module scope is consulted instead
/// (a global read). Any non-call or non-plain binding makes the name
/// unresolvable and yields an empty list.
fn assigned_call_values<'a>(
    name: &str,
    function: &'a StmtFunctionDef,
    module_body: &'a [Stmt],
) -> Vec<&'a ExprCall> {
    let mut found = AssignedValues::default();
    collect_assigned_calls(&function.body, name, &mut found);
    if !found.bound {
        collect_assigned_calls(module_body, name, &mut found);
    }
    if found.tainted {
        Vec::new()
    } else {
        found.calls
    }
}

#[derive(Default)]
struct AssignedValues<'a> {
    /// Any binding event for the name in this scope.
    bound: bool,
    /// A binding that is not a plain `name = <call>` assignment.
    tainted: bool,
    /// `name = <call>` call sites in binding order.
    calls: Vec<&'a ExprCall>,
}

fn collect_assigned_calls<'a>(stmts: &'a [Stmt], name: &str, found: &mut AssignedValues<'a>) {
    for stmt in stmts {
        match stmt {
            Stmt::Assign(assign) => record_assign(assign, name, found),
            Stmt::AnnAssign(assign) => record_ann_assign(assign, name, found),
            _ => {
                if stmt_store_names(stmt).iter().any(|bound| bound == name) {
                    found.bound = true;
                    found.tainted = true;
                }
            }
        }
        // Walrus targets bind the name without a call value.
        record_walrus_bindings(stmt, name, found);
        if !matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            for body in crate::support::child_bodies(stmt) {
                collect_assigned_calls(body, name, found);
            }
        }
    }
}

/// A `name = <call>` target contributes the call; any other binding of
/// `name` in the assignment taints the resolution.
fn record_assign<'a>(
    assign: &'a ruff_python_ast::StmtAssign,
    name: &str,
    found: &mut AssignedValues<'a>,
) {
    let mut binds = false;
    let mut plain = false;
    for target in &assign.targets {
        if matches!(target, Expr::Name(target_name)
            if target_name.id.as_str() == name)
        {
            plain = true;
        }
        let mut names = Vec::new();
        collect_target_names(target, &mut names);
        if names.iter().any(|bound| bound == name) {
            binds = true;
        }
    }
    if !binds {
        return;
    }
    found.bound = true;
    if !plain {
        found.tainted = true;
    } else if let Expr::Call(call) = assign.value.as_ref() {
        found.calls.push(call);
    } else {
        found.tainted = true;
    }
}

/// An annotated `name: T = <call>` contributes the call; a bare annotation
/// or non-call value taints the resolution.
fn record_ann_assign<'a>(
    assign: &'a ruff_python_ast::StmtAnnAssign,
    name: &str,
    found: &mut AssignedValues<'a>,
) {
    let mut names = Vec::new();
    collect_target_names(&assign.target, &mut names);
    if !names.iter().any(|bound| bound == name) {
        return;
    }
    found.bound = true;
    match assign.value.as_deref() {
        Some(Expr::Call(call)) => found.calls.push(call),
        _ => found.tainted = true,
    }
}

/// Walrus targets anywhere in `stmt`'s expressions bind `name` without a
/// call value.
fn record_walrus_bindings(stmt: &Stmt, name: &str, found: &mut AssignedValues<'_>) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::Named(named) = expr {
                let mut names = Vec::new();
                collect_target_names(&named.target, &mut names);
                if names.iter().any(|bound| bound == name) {
                    found.bound = true;
                    found.tainted = true;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8400")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8400_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: endpoints that fall through without
        // returning None anchor on the return statement.
        let issues = found(concat!(
            "from fastapi import FastAPI\n",
            "app = FastAPI()\n",
            "\n",
            "@app.delete(\"/resource/{id}\", status_code=204)\n",
            "def delete_resource(id: int):\n",
            "    return {'deleted': id}\n",
        ));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].range.start, pos(6, 4));
        assert_eq!(issues[0].range.end, pos(6, 26));
    }

    #[test]
    fn s8400_accepts_the_sonar_compliant_examples() {
        // Sonar's Compliant examples: explicit `return None` and a bare
        // `Response(status_code=204)` produce empty bodies.
        assert!(
            found(concat!(
                "from fastapi import FastAPI, Response\n",
                "app = FastAPI()\n",
                "\n",
                "@app.delete(\"/resource/{id}\", status_code=204)\n",
                "def delete_resource(id: int):\n",
                "    return None\n",
                "\n",
                "@app.put(\"/resource/{id}/archive\", status_code=204)\n",
                "def archive_resource(id: int):\n",
                "    return Response(status_code=204)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8400_flags_bodies_and_invalid_response_calls() {
        // A dict body, a Response with content, and a Response with a
        // non-204 status all flag; the assigned invalid call adds a
        // secondary location.
        let issues = found(concat!(
            "from fastapi import FastAPI, Response\n",
            "app = FastAPI()\n",
            "\n",
            "@app.delete(\"/a\", status_code=204)\n",
            "def with_body():\n",
            "    return Response(content='{}')\n",
            "\n",
            "@app.delete(\"/b\", status_code=204)\n",
            "def wrong_status():\n",
            "    return Response(status_code=200)\n",
            "\n",
            "@app.delete(\"/c\", status_code=204)\n",
            "def via_name():\n",
            "    resp = Response(content='x')\n",
            "    return resp\n",
        ));
        assert_eq!(issues.len(), 3);
        assert_eq!(issues[0].range.start, pos(6, 4));
        assert_eq!(issues[1].range.start, pos(10, 4));
        assert_eq!(issues[2].range.start, pos(15, 4));
        assert_eq!(issues[2].flows.len(), 1);
        assert_eq!(issues[2].flows[0].locations[0].range.start, pos(14, 11));
        assert_eq!(
            issues[2].flows[0].locations[0].message,
            "Response is assigned here"
        );
    }

    #[test]
    fn s8400_ignores_other_status_codes_and_non_fastapi() {
        // Endpoints without status_code=204 and route decorators on
        // non-FastAPI objects stay silent.
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "app = FastAPI()\n",
                "\n",
                "@app.delete(\"/a\", status_code=200)\n",
                "def ok():\n",
                "    return {'deleted': True}\n",
                "\n",
                "@app.delete(\"/b\")\n",
                "def defaulted():\n",
                "    return {'deleted': True}\n",
                "\n",
                "class App:\n",
                "    def delete(self, path, status_code=None):\n",
                "        return lambda f: f\n",
                "other = App()\n",
                "\n",
                "@other.delete(\"/c\", status_code=204)\n",
                "def not_fastapi():\n",
                "    return {'deleted': True}\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8400_flags_bare_fallthrough_and_ignores_nested_returns() {
        // A bare `return` is a valid empty body, but a value-returning
        // statement flags; returns inside nested functions are not the
        // endpoint's.
        let issues = found(concat!(
            "from fastapi import FastAPI\n",
            "app = FastAPI()\n",
            "\n",
            "@app.delete(\"/a\", status_code=204)\n",
            "def empty():\n",
            "    return\n",
            "\n",
            "@app.delete(\"/b\", status_code=204)\n",
            "def nested():\n",
            "    def helper():\n",
            "        return {'x': 1}\n",
            "    return\n",
        ));
        assert!(issues.is_empty());
    }
}
