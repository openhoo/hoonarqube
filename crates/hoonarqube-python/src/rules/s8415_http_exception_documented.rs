use std::collections::{HashSet, VecDeque};

use ruff_python_ast::{Expr, ExprCall, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{
    WebFrameworkFacts, is_fastapi_verb, is_http_exception, keyword_argument,
    nth_or_keyword_argument,
};
use crate::support::{issue_at, string_literal_text};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8415";
const MAX_CALL_GRAPH_NODES: usize = 100;

/// python:S8415 — `raise HTTPException(status_code=N)` produces an error
/// response that stays invisible in the generated `OpenAPI` document unless
/// the endpoint decorator's `responses` mapping documents `N`. Sonar flags
/// the `HTTPException` callee of every raise reachable from a `FastAPI`
/// route-verb endpoint (directly or through same-file helper calls, capped
/// at 100 call-graph nodes) whose status code is absent from the union of
/// the endpoint's `responses` dict keys. A `responses` argument that is
/// not a dict literal makes the endpoint unanalyzable; a raise without a
/// resolvable integer status code stays silent.
pub(crate) fn check_s8415_http_exception_documented(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut reported: HashSet<TextRange> = HashSet::new();
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        let Some(documented) = documented_status_codes(&facts, function) else {
            continue;
        };
        for (callee, status) in http_exception_raises(&facts, file_ctx, function) {
            if documented.contains(&status) || !reported.insert(callee.range()) {
                continue;
            }
            let message = format!(
                "Document this HTTPException with status code {status} in the \"responses\" parameter."
            );
            issues.push(issue_at(RULE_KEY, &message, callee.range(), index, source));
        }
    }
    issues
}

/// Union of status codes documented by the endpoint's route decorators, or
/// `None` when the function is not a `FastAPI` endpoint or a `responses`
/// argument is not analyzable as a dict literal.
fn documented_status_codes(
    facts: &WebFrameworkFacts<'_>,
    function: &StmtFunctionDef,
) -> Option<HashSet<i64>> {
    let mut documented = HashSet::new();
    let mut is_endpoint = false;
    for decorator in &function.decorator_list {
        let Expr::Call(call) = &decorator.expression else {
            continue;
        };
        if !facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| is_fastapi_verb(&fqn))
        {
            continue;
        }
        is_endpoint = true;
        if let Some(responses) = keyword_argument(call, "responses") {
            let Expr::Dict(dict) = responses else {
                return None;
            };
            for item in &dict.items {
                if let Some(key) = &item.key
                    && let Some(code) = status_code_of(facts, key)
                {
                    documented.insert(code);
                }
            }
        }
    }
    is_endpoint.then_some(documented)
}

/// `(HTTPException callee, status code)` pairs raised by the endpoint body
/// or by same-file functions it transitively calls (Sonar's forward call
/// graph, capped at 100 nodes).
fn http_exception_raises<'a>(
    facts: &WebFrameworkFacts<'a>,
    file_ctx: &FileContext<'a>,
    function: &'a StmtFunctionDef,
) -> Vec<(&'a Expr, i64)> {
    let mut raises = Vec::new();
    let mut visited: HashSet<TextRange> = HashSet::new();
    let mut queue = VecDeque::from([function]);
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.range()) || visited.len() > MAX_CALL_GRAPH_NODES {
            continue;
        }
        let nested = nested_ranges(facts, file_ctx, current);
        for (raise, call) in direct_raises(file_ctx, current, &nested) {
            if let Some(code) = http_exception_status(facts, call) {
                raises.push((call.func.as_ref(), code));
            }
            let _ = raise;
        }
        for call in direct_calls(file_ctx, current, &nested) {
            if let Some(target) = facts.resolve_function(call) {
                queue.push_back(target);
            }
        }
    }
    raises
}

/// Ranges of function defs and lambdas nested inside `function`, whose
/// contents Sonar's visitor skips for the outer endpoint.
fn nested_ranges(
    facts: &WebFrameworkFacts<'_>,
    file_ctx: &FileContext<'_>,
    function: &StmtFunctionDef,
) -> Vec<TextRange> {
    let body = body_range(function);
    let mut ranges: Vec<TextRange> = file_ctx
        .functions
        .iter()
        .map(Ranged::range)
        .chain(facts.lambdas().map(Ranged::range))
        .filter(|range| *range != function.range() && body.contains_range(*range))
        .collect();
    ranges.sort_by_key(|range| range.start().to_u32());
    ranges
}

fn body_range(function: &StmtFunctionDef) -> TextRange {
    function
        .body
        .first()
        .zip(function.body.last())
        .map_or(function.range(), |(first, last)| {
            TextRange::new(first.range().start(), last.range().end())
        })
}

fn in_nested(range: TextRange, nested: &[TextRange]) -> bool {
    nested.iter().any(|inner| inner.contains_range(range))
}

/// `raise` statements directly inside `function`'s body paired with the
/// raised call expression.
fn direct_raises<'a>(
    file_ctx: &FileContext<'a>,
    function: &'a StmtFunctionDef,
    nested: &[TextRange],
) -> Vec<(&'a Stmt, &'a ExprCall)> {
    let body = body_range(function);
    file_ctx
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Raise(raise) => Some((*stmt, raise)),
            _ => None,
        })
        .filter(|(stmt, _)| body.contains_range(stmt.range()) && !in_nested(stmt.range(), nested))
        .filter_map(|(stmt, raise)| match raise.exc.as_deref() {
            Some(Expr::Call(call)) => Some((stmt, call)),
            _ => None,
        })
        .collect()
}

/// Call expressions directly inside `function`'s body.
fn direct_calls<'a>(
    file_ctx: &FileContext<'a>,
    function: &'a StmtFunctionDef,
    nested: &[TextRange],
) -> Vec<&'a ExprCall> {
    let body = body_range(function);
    file_ctx
        .calls
        .iter()
        .filter(|call| body.contains_range(call.range()) && !in_nested(call.range(), nested))
        .copied()
        .collect()
}

/// Status code of a `raise HTTPException(...)` call, or `None` when the
/// callee is not `FastAPI`'s `HTTPException` or the code is not resolvable.
fn http_exception_status(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> Option<i64> {
    if !facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| is_http_exception(&fqn))
    {
        return None;
    }
    status_code_of(facts, nth_or_keyword_argument(call, 0, "status_code")?)
}

/// Integer status code of an expression: a numeric literal, a string
/// literal holding an integer, or a name bound to a single such value.
fn status_code_of(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Name(name) => facts
            .single_assigned_value(name.id.as_str(), expr.range())
            .and_then(|value| status_code_of(facts, value)),
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64(),
            _ => None,
        },
        Expr::StringLiteral(_) => string_literal_text(expr)?.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<(hoonarqube_ir::Range, String)> {
        findings(&scan(source), "python:S8415")
            .into_iter()
            .map(|issue| (issue.range.clone(), issue.message.clone()))
            .collect()
    }

    #[test]
    fn s8415_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: the undocumented 404 raise flags on
        // the `HTTPException` callee (line 8, columns 14-27).
        let ranges = found(concat!(
            "from fastapi import FastAPI, HTTPException\n",
            "\n",
            "app = FastAPI()\n",
            "\n",
            "@app.get(\"/users/{user_id}\")\n",
            "def get_user(user_id: int):\n",
            "    if user_id not in users:\n",
            "        raise HTTPException(status_code=404, detail=\"User not found\")\n",
            "    return users[user_id]\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0.start, pos(8, 14));
        assert_eq!(ranges[0].0.end, pos(8, 27));
        assert_eq!(
            ranges[0].1,
            "Document this HTTPException with status code 404 in the \"responses\" parameter."
        );
    }

    #[test]
    fn s8415_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI, HTTPException\n",
                "\n",
                "app = FastAPI()\n",
                "\n",
                "@app.get(\n",
                "    \"/users/{user_id}\",\n",
                "    responses={404: {\"description\": \"User not found\"}}\n",
                ")\n",
                "def get_user(user_id: int):\n",
                "    if user_id not in users:\n",
                "        raise HTTPException(status_code=404, detail=\"User not found\")\n",
                "    return users[user_id]\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8415_flags_only_the_undocumented_status_code() {
        // Two 422 raises share one documented code; the undocumented 400
        // still flags.
        let ranges = found(concat!(
            "from fastapi import FastAPI, HTTPException\n",
            "\n",
            "app = FastAPI()\n",
            "\n",
            "@app.post(\"/items\", responses={422: {\"description\": \"Invalid\"}})\n",
            "def create_item(item):\n",
            "    if not item.name:\n",
            "        raise HTTPException(status_code=422, detail=\"Name is required\")\n",
            "    if len(item.name) > 100:\n",
            "        raise HTTPException(status_code=422, detail=\"Name too long\")\n",
            "    raise HTTPException(status_code=400, detail=\"Bad request\")\n",
            "    return item\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0.start, pos(11, 10));
    }

    #[test]
    fn s8415_follows_same_file_helper_calls() {
        // Sonar's call graph attributes helper raises to the endpoint; the
        // shared helper is reported once for the file.
        let ranges = found(concat!(
            "from fastapi import FastAPI, HTTPException\n",
            "\n",
            "app = FastAPI()\n",
            "\n",
            "def require_user(user_id):\n",
            "    if user_id is None:\n",
            "        raise HTTPException(status_code=404, detail=\"Missing\")\n",
            "\n",
            "@app.get(\"/users/{user_id}\")\n",
            "def get_user(user_id: int):\n",
            "    require_user(user_id)\n",
            "    return {\"id\": user_id}\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0.start, pos(7, 14));
    }

    #[test]
    fn s8415_ignores_non_endpoint_and_unanalyzable_responses() {
        // A plain function raising HTTPException and an endpoint whose
        // `responses` is not a dict literal both stay silent.
        assert!(
            found(concat!(
                "from fastapi import FastAPI, HTTPException\n",
                "\n",
                "app = FastAPI()\n",
                "RESPONSES = {404: {\"description\": \"x\"}}\n",
                "\n",
                "def helper():\n",
                "    raise HTTPException(status_code=404)\n",
                "\n",
                "@app.get(\"/items\", responses=RESPONSES)\n",
                "def get_items():\n",
                "    raise HTTPException(status_code=500)\n",
            ))
            .is_empty()
        );
    }
}
