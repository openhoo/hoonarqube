use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::dotted_name;
use crate::support::is_call_method;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

pub(crate) fn check_s5122_cors_wildcard(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_wildcard_dicts(index, source, file_ctx, &mut issues);
    flag_wildcard_calls(index, source, file_ctx, &mut issues);
    flag_wildcard_assignments(index, source, file_ctx, &mut issues);
    issues
}

fn is_wildcard(expr: &Expr) -> bool {
    string_literal_text(expr).as_deref() == Some("*")
}

fn has_wildcard_origin(expr: &Expr) -> bool {
    match expr {
        Expr::Dict(dict) => dict.items.iter().any(|item| {
            let is_origins =
                item.key.as_ref().and_then(string_literal_text).as_deref() == Some("origins");
            (is_origins && contains_wildcard(&item.value)) || has_wildcard_origin(&item.value)
        }),
        Expr::List(list) => list.elts.iter().any(contains_wildcard),
        Expr::Tuple(tuple) => tuple.elts.iter().any(contains_wildcard),
        _ => false,
    }
}

fn contains_wildcard(expr: &Expr) -> bool {
    is_wildcard(expr)
        || match expr {
            Expr::Dict(dict) => dict.items.iter().any(|item| contains_wildcard(&item.value)),
            Expr::List(list) => list.elts.iter().any(contains_wildcard),
            Expr::Tuple(tuple) => tuple.elts.iter().any(contains_wildcard),
            _ => false,
        }
}

fn flag_wildcard_dicts(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    for expr in &file_ctx.exprs {
        if let Expr::Dict(dict) = expr {
            for item in &dict.items {
                let Some(key) = item.key.as_ref() else {
                    continue;
                };
                if string_literal_text(key).as_deref() == Some(CORS_WILDCARD_HEADER)
                    && is_wildcard(&item.value)
                {
                    push_issue(dict.range(), index, source, issues);
                }
            }
        }
    }
}

fn flag_wildcard_calls(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    let cors_paths = cors_call_paths(file_ctx);
    let wildcard_resources = wildcard_resource_bindings(file_ctx);
    for call in &file_ctx.calls {
        if !is_cors_call(call, &cors_paths) {
            continue;
        }
        let direct_wildcard = keyword_value(&call.arguments, "origins").is_some_and(is_wildcard);
        let resource_wildcard = keyword_value(&call.arguments, "resources").is_some_and(|value| {
            has_wildcard_origin(value)
                || matches!(value, Expr::Name(name) if wildcard_resources.contains(name.id.as_str()))
        });
        if direct_wildcard || resource_wildcard {
            push_issue(call.range(), index, source, issues);
        }
    }
}

fn cors_call_paths(file_ctx: &FileContext<'_>) -> HashSet<String> {
    let mut paths = HashSet::new();
    for import in &file_ctx.imports {
        collect_cors_call_paths(import, &mut paths);
    }
    paths
}
fn collect_cors_call_paths(import: &AnyImport<'_>, paths: &mut HashSet<String>) {
    match import {
        AnyImport::Plain(import) => collect_plain_cors_call_paths(import, paths),
        AnyImport::From(import) => collect_from_cors_call_paths(import, paths),
    }
}

fn collect_plain_cors_call_paths(
    import: &ruff_python_ast::StmtImport,
    paths: &mut HashSet<String>,
) {
    for alias in &import.names {
        if alias.name.as_str() == "flask_cors" {
            let local = alias.asname.as_deref().unwrap_or("flask_cors");
            paths.insert(format!("{local}.CORS"));
        }
    }
}

fn collect_from_cors_call_paths(
    import: &ruff_python_ast::StmtImportFrom,
    paths: &mut HashSet<String>,
) {
    let Some(module) = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str)
    else {
        return;
    };
    if module != "flask_cors" {
        return;
    }
    for alias in &import.names {
        if alias.name.as_str() == "CORS" {
            paths.insert(alias.asname.as_deref().unwrap_or("CORS").to_string());
        }
    }
}

fn is_cors_call(call: &ruff_python_ast::ExprCall, cors_paths: &HashSet<String>) -> bool {
    is_call_method(call, "CORS")
        || dotted_name(&call.func).is_some_and(|path| cors_paths.contains(&path))
}

fn wildcard_resource_bindings(file_ctx: &FileContext<'_>) -> HashSet<String> {
    let mut bindings = HashSet::new();
    for statement in &file_ctx.stmts {
        let Stmt::Assign(assign) = statement else {
            continue;
        };
        for target in &assign.targets {
            let Expr::Name(name) = target else {
                continue;
            };
            if has_wildcard_origin(&assign.value) {
                bindings.insert(name.id.as_str().to_string());
            } else {
                bindings.remove(name.id.as_str());
            }
        }
    }
    bindings
}

fn flag_wildcard_assignments(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    for stmt in &file_ctx.stmts {
        if let Stmt::Assign(assign) = stmt {
            let sets_wildcard = is_wildcard(&assign.value);
            for target in &assign.targets {
                if let Expr::Subscript(subscript) = target {
                    let header = subscript.slice.as_ref();
                    if sets_wildcard
                        && string_literal_text(header).as_deref() == Some(CORS_WILDCARD_HEADER)
                    {
                        push_issue(assign.range(), index, source, issues);
                    }
                }
            }
        }
    }
}

fn push_issue(
    range: ruff_text_size::TextRange,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    issues.push(issue_at(
        "python:S5122",
        "Make sure this permissive CORS policy is safe here.",
        range,
        index,
        source,
    ));
}

// --- python:S5122 — CORS policy restricted to trusted origins -----------------

const CORS_WILDCARD_HEADER: &str = "Access-Control-Allow-Origin";

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5122_flags_nested_flask_cors_resource_wildcard() {
        let flagged = concat!(
            "from flask import Flask, Response, request\n",
            "from flask_cors import CORS\n",
            "\n",
            "app = Flask(__name__)\n",
            "CORS(app, resources={r\"/*\": {\"origins\": \"*\"}})\n",
            "origin = request.headers[\"ORIGIN\"]\n",
            "resp = Response()\n",
            "resp.headers[\"Access-Control-Allow-Origin\"] = origin\n"
        );
        let report = scan(flagged);
        let found = findings(&report, "python:S5122");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Make sure this permissive CORS policy is safe here."
        );
        assert_eq!(
            (
                found[0].range.start.line,
                found[0].range.start.column,
                found[0].range.end.line,
                found[0].range.end.column
            ),
            (5, 0, 5, 46)
        );
    }

    #[test]
    fn s5122_preserves_trusted_resource_origins_and_explicit_lists() {
        let safe = concat!(
            "from flask import Flask, Response, request\n",
            "from flask_cors import CORS\n",
            "\n",
            "app = Flask(__name__)\n",
            "TRUSTED_ORIGINS = [\"https://example.com\"]\n",
            "CORS(app, resources={r\"/*\": {\"origins\": TRUSTED_ORIGINS}})\n",
            "origin = request.headers[\"ORIGIN\"]\n",
            "resp = Response()\n",
            "if origin in TRUSTED_ORIGINS:\n",
            "    resp.headers[\"Access-Control-Allow-Origin\"] = origin\n"
        );
        assert!(findings(&scan(safe), "python:S5122").is_empty());
        let near_miss = concat!(
            "from flask import Flask\n",
            "from flask_cors import CORS\n",
            "\n",
            "app = Flask(__name__)\n",
            "CORS(app, resources={r\"/public\": {\"origins\": [\"https://example.com\"]}})\n"
        );
        assert!(findings(&scan(near_miss), "python:S5122").is_empty());
    }

    #[test]
    fn s5122_retains_direct_header_controls() {
        let header_report = scan("response.headers[\"Access-Control-Allow-Origin\"] = \"*\"\n");
        let found = findings(&header_report, "python:S5122");
        assert_eq!(found.len(), 1);
    }
    #[test]
    fn s5122_supports_cors_aliases_and_wildcard_origin_lists() {
        let source = concat!(
            "from flask_cors import CORS as apply_cors\n",
            "\n",
            "RESOURCES = {r\"/*\": {\"origins\": [\"*\"]}}\n",
            "apply_cors(app, resources=RESOURCES)\n"
        );
        assert_eq!(findings(&scan(source), "python:S5122").len(), 1);
    }
}
