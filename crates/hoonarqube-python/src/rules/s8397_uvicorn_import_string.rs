use ruff_python_ast::{ArgOrKeyword, Expr, ExprCall};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{NameResolution, WebFrameworkFacts, issue_at, keyword_argument};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8397";

/// python:S8397 — `uvicorn.run()` cannot pass an application object to
/// the new processes it spawns for `reload`, `debug`, or `workers`, so
/// the app must be given as an import string (`"main:app"`). Sonar
/// flags the app argument when it is a `FastAPI` application object (not
/// a string) and `reload`/`debug` is literally `True` or bound to
/// `True`, or `workers` is a decimal literal greater than one (or bound
/// to one). The message names the offending parameters in the order
/// `reload`, `workers`, `debug`.
pub(crate) fn check_s8397_uvicorn_import_string(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    file_ctx
        .calls
        .iter()
        .filter_map(|call| uvicorn_run_issue(&facts, call, index, source))
        .collect()
}

/// The finding for one `uvicorn.run(...)` call: the app argument when it
/// is a `FastAPI` object and `reload`/`debug`/`workers` force new
/// processes.
fn uvicorn_run_issue(
    facts: &WebFrameworkFacts<'_>,
    call: &ExprCall,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    if facts
        .expr_fqn(&call.func)
        .is_none_or(|fqn| fqn != "uvicorn.run")
    {
        return None;
    }
    let first = call.arguments.iter_source_order().next()?;
    let app_expr = match first {
        ArgOrKeyword::Arg(expr) => expr,
        ArgOrKeyword::Keyword(keyword) => &keyword.value,
    };
    if matches!(app_expr, Expr::Starred(_)) {
        return None;
    }

    let mut problematic: Vec<&str> = Vec::new();
    if has_true_keyword(facts, call, "reload") {
        problematic.push("reload");
    }
    if has_workers_keyword(facts, call, source) {
        problematic.push("workers");
    }
    if has_true_keyword(facts, call, "debug") {
        problematic.push("debug");
    }
    if problematic.is_empty() || is_string(facts, app_expr) || !is_fastapi_app(facts, app_expr) {
        return None;
    }
    Some(issue_at(
        RULE_KEY,
        &build_message(&problematic),
        app_expr.range(),
        index,
        source,
    ))
}

/// `reload`/`debug` is `True` or a name bound to `True`.
fn has_true_keyword(facts: &WebFrameworkFacts<'_>, call: &ExprCall, name: &str) -> bool {
    let Some(expr) = keyword_argument(call, name) else {
        return false;
    };
    is_true_literal(facts, expr)
}

fn is_true_literal(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    // Sonar resolves a name through `singleAssignedValue` exactly once
    // and checks the assigned expression's first token for "True".
    let expr = match expr {
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), expr.range()) {
            NameResolution::Value(value) => value,
            _ => return false,
        },
        _ => expr,
    };
    matches!(expr, Expr::BooleanLiteral(boolean) if boolean.value)
}

/// `workers` is a decimal integer literal greater than one, or a name
/// bound to one. Sonar parses the literal's decimal text, so hex,
/// underscored, and float spellings do not count.
fn has_workers_keyword(facts: &WebFrameworkFacts<'_>, call: &ExprCall, source: &str) -> bool {
    let Some(expr) = keyword_argument(call, "workers") else {
        return false;
    };
    decimal_greater_than_one(facts, expr, source)
}

fn decimal_greater_than_one(facts: &WebFrameworkFacts<'_>, expr: &Expr, source: &str) -> bool {
    // Same single-hop resolution: `singleAssignedValue` once, then the
    // assigned expression must be a numeric literal.
    let expr = match expr {
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), expr.range()) {
            NameResolution::Value(value) => value,
            _ => return false,
        },
        _ => expr,
    };
    matches!(expr, Expr::NumberLiteral(_))
        && source[expr.range()]
            .trim()
            .parse::<i64>()
            .is_ok_and(|value| value > 1)
}

/// Whether `expr` is a string literal or a name bound to one.
fn is_string(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) | Expr::FString(_) => true,
        Expr::Name(name) => match facts.resolve_name(name.id.as_str(), expr.range()) {
            NameResolution::Value(value) => is_string(facts, value),
            _ => false,
        },
        _ => false,
    }
}

/// Whether `expr` is a `FastAPI()` construction, following local
/// aliases (`app_variable = app`).
fn is_fastapi_app(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    facts
        .expr_fqn(expr)
        .is_some_and(|fqn| fqn == "fastapi.applications.FastAPI")
}

fn build_message(problematic: &[&str]) -> String {
    let params = match problematic {
        [only] => format!("'{only}'"),
        [first, second] => format!("'{first}' and '{second}'"),
        many => {
            let (last, rest) = many.split_last().expect("non-empty");
            let quoted = rest
                .iter()
                .map(|param| format!("'{param}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{quoted}, and '{last}'")
        }
    };
    format!("Pass the application as an import string when using {params}.")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8397")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8397_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: app object with reload/debug/
        // workers, including values bound through variables.
        let issues = found(concat!(
            "import uvicorn\n",
            "from fastapi import FastAPI\n",
            "\n",
            "app = FastAPI()\n",
            "app_variable = app\n",
            "enable_reload = True\n",
            "num_workers = 4\n",
            "\n",
            "uvicorn.run(app, reload=True)\n",
            "uvicorn.run(app, debug=True, reload=False)\n",
            "uvicorn.run(app, workers=2)\n",
            "uvicorn.run(app, workers=3, debug=True)\n",
            "uvicorn.run(app_variable, host=\"0.0.0.0\", debug=True, reload=True)\n",
            "uvicorn.run(app, reload=True, workers=2, debug=True)\n",
            "uvicorn.run(app, reload=enable_reload)\n",
            "uvicorn.run(app, workers=num_workers)\n",
            "uvicorn.run(app, reload=False, workers=2)\n",
        ));
        assert_eq!(issues.len(), 9);
        assert_eq!(
            issues[0].message,
            "Pass the application as an import string when using 'reload'."
        );
        assert_eq!(
            issues[1].message,
            "Pass the application as an import string when using 'debug'."
        );
        assert_eq!(
            issues[3].message,
            "Pass the application as an import string when using 'workers' and 'debug'."
        );
        assert_eq!(
            issues[5].message,
            "Pass the application as an import string when using 'reload', 'workers', and 'debug'."
        );
        // The app expression `app` anchors the finding on line 9.
        assert_eq!(issues[0].range.start, pos(9, 12));
        assert_eq!(issues[0].range.end, pos(9, 15));
    }

    #[test]
    fn s8397_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "import uvicorn\n",
                "from fastapi import FastAPI\n",
                "\n",
                "app = FastAPI()\n",
                "app_import_string = \"main:app\"\n",
                "enable_reload = False\n",
                "num_workers = 1\n",
                "config = {\"workers\": 4}\n",
                "args = (app,)\n",
                "\n",
                "def unknown():\n",
                "    pass\n",
                "\n",
                "def get_workers():\n",
                "    return 4\n",
                "\n",
                "app_instance = unknown()\n",
                "\n",
                "uvicorn.run(\"main:app\", reload=True)\n",
                "uvicorn.run(\"main:app\", debug=True)\n",
                "uvicorn.run(\"main:app\", workers=4)\n",
                "uvicorn.run(app, host=\"0.0.0.0\", port=8000)\n",
                "uvicorn.run(app, workers=1)\n",
                "uvicorn.run(app, workers=num_workers)\n",
                "uvicorn.run(app, workers=get_workers())\n",
                "uvicorn.run(app, **config)\n",
                "uvicorn.run(app_import_string, host=\"0.0.0.0\", reload=True)\n",
                "uvicorn.run(app_instance, host=\"0.0.0.0\", reload=True)\n",
                "uvicorn.run(app, reload=enable_reload)\n",
                "uvicorn.run()\n",
                "uvicorn.run(*args, reload=True)\n",
                "uvicorn.run(app, debug=False, host=\"0.0.0.0\")\n",
                "uvicorn.run(app, debug=unknown(), host=\"0.0.0.0\")\n",
                "uvicorn.run(app, debug=unknown_var, host=\"0.0.0.0\")\n",
                "uvicorn.run(app, reload=False, workers=1)\n",
            ))
            .is_empty()
        );
    }
}
