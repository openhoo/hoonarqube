use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, is_fastapi_route, keyword_argument};
use crate::support::{issue_at, string_literal_text};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8412";
const MESSAGE: &str =
    "Replace this generic \"route()\" decorator with a specific HTTP method decorator.";

/// Single-method spellings Sonar accepts for the quick-fixable finding:
/// the eight HTTP verbs in upper or lower case.
const SINGLE_HTTP_METHODS: [&str; 16] = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "get", "post", "put",
    "delete", "patch", "options", "head", "trace",
];

/// python:S8412 — `FastAPI` offers a decorator per HTTP method, so the
/// generic `@app.route()`/`@router.route()` with a `methods` list is
/// unidiomatic. Sonar flags the decorator's callee expression only when
/// `methods` is a list literal holding exactly one string literal naming a
/// single HTTP method; multi-method lists, non-list values, and missing
/// `methods` stay silent.
pub(crate) fn check_s8412_generic_route_decorator(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        for decorator in &function.decorator_list {
            let Expr::Call(call) = &decorator.expression else {
                continue;
            };
            if !facts
                .expr_fqn(&call.func)
                .is_some_and(|fqn| is_fastapi_route(&fqn))
            {
                continue;
            }
            let Some(Expr::List(methods)) = keyword_argument(call, "methods") else {
                continue;
            };
            let [method] = methods.elts.as_slice() else {
                continue;
            };
            let Some(method) = string_literal_text(method) else {
                continue;
            };
            if SINGLE_HTTP_METHODS.contains(&method.as_str()) {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE,
                    call.func.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8412")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8412_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: `methods=["GET"]`, `["POST"]`,
        // `["DELETE"]` on the app and `["GET"]` on an APIRouter — the
        // callee `app.route`/`router.route` anchors each finding.
        let ranges = found(concat!(
            "from fastapi import FastAPI, APIRouter\n",
            "\n",
            "app = FastAPI()\n",
            "router = APIRouter()\n",
            "\n",
            "@app.route(\"/users\", methods=[\"GET\"])\n",
            "def get_users():\n",
            "    return {\"users\": []}\n",
            "\n",
            "@app.route(\"/users\", methods=[\"POST\"])\n",
            "def create_user(user):\n",
            "    return {\"user\": user}\n",
            "\n",
            "@app.route(\"/items/{item_id}\", methods=[\"DELETE\"])\n",
            "def delete_item(item_id: int):\n",
            "    return {\"deleted\": item_id}\n",
            "\n",
            "@router.route(\"/items\", methods=[\"GET\"])\n",
            "def list_items():\n",
            "    return {\"items\": []}\n",
        ));
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0].start, pos(6, 1));
        assert_eq!(ranges[0].end, pos(6, 10));
        assert_eq!(ranges[3].start, pos(18, 1));
        assert_eq!(ranges[3].end, pos(18, 13));
    }

    #[test]
    fn s8412_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI, APIRouter\n",
                "\n",
                "app = FastAPI()\n",
                "router = APIRouter()\n",
                "\n",
                "@app.get(\"/users\")\n",
                "def get_users():\n",
                "    return {\"users\": []}\n",
                "\n",
                "@router.get(\"/items\")\n",
                "def list_items():\n",
                "    return {\"items\": []}\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8412_ignores_multi_method_and_non_literal_methods() {
        // A two-method list and a non-list `methods` value are outside
        // Sonar's single-method trigger.
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "\n",
                "app = FastAPI()\n",
                "METHODS = [\"GET\"]\n",
                "\n",
                "@app.route(\"/users\", methods=[\"GET\", \"POST\"])\n",
                "def users():\n",
                "    return {}\n",
                "\n",
                "@app.route(\"/other\", methods=METHODS)\n",
                "def other():\n",
                "    return {}\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8412_ignores_route_on_unrelated_receivers() {
        // A `route` decorator on an object that is not a FastAPI app or
        // APIRouter (here a plain Flask-like name) stays silent.
        assert!(
            found(concat!(
                "app = object()\n",
                "\n",
                "@app.route(\"/users\", methods=[\"GET\"])\n",
                "def get_users():\n",
                "    return {\"users\": []}\n",
            ))
            .is_empty()
        );
    }
}
