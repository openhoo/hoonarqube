use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::{
    WebFrameworkFacts, is_api_router_call, is_include_router, keyword_argument, keyword_name_range,
    nth_or_keyword_argument,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8413";
const MESSAGE: &str =
    "Define the prefix in the \"APIRouter\" constructor instead of in \"include_router()\".";

/// python:S8413 — a router's URL prefix belongs in its `APIRouter()`
/// constructor so the router module is self-describing. Sonar flags the
/// `prefix` keyword name of a `FastAPI|APIRouter.include_router` call when
/// the included router is a bare name bound to exactly one
/// `APIRouter(...)` call that itself has no `prefix` argument. A router
/// already constructed with a prefix, or not bound to a single
/// `APIRouter()` call, stays silent.
pub(crate) fn check_s8413_router_prefix_in_include(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| is_include_router(&fqn))
        {
            continue;
        }
        if keyword_argument(call, "prefix").is_none() {
            continue;
        }
        let Some(Expr::Name(router)) = nth_or_keyword_argument(call, 0, "router") else {
            continue;
        };
        let Some(Expr::Call(binding)) =
            facts.single_assigned_value(router.id.as_str(), router.range())
        else {
            continue;
        };
        if !is_api_router_call(&facts, binding) || keyword_argument(binding, "prefix").is_some() {
            continue;
        }
        if let Some(range) = keyword_name_range(call, "prefix") {
            issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8413")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8413_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `router` is constructed without a
        // prefix and `include_router` supplies one — the `prefix` keyword
        // name anchors the finding (line 10, columns 27-33).
        let ranges = found(concat!(
            "from fastapi import APIRouter, FastAPI\n",
            "\n",
            "router = APIRouter()\n",
            "\n",
            "@router.get(\"/users\")\n",
            "def list_users():\n",
            "    return [\"user1\", \"user2\"]\n",
            "\n",
            "app = FastAPI()\n",
            "app.include_router(router, prefix=\"/api/v1\")\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(10, 27));
        assert_eq!(ranges[0].end, pos(10, 33));
    }

    #[test]
    fn s8413_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from fastapi import APIRouter, FastAPI\n",
                "\n",
                "router = APIRouter(prefix=\"/api/v1\")\n",
                "\n",
                "@router.get(\"/users\")\n",
                "def list_users():\n",
                "    return [\"user1\", \"user2\"]\n",
                "\n",
                "app = FastAPI()\n",
                "app.include_router(router)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8413_ignores_router_constructed_with_prefix() {
        // The constructor already carries a prefix, so the include-time
        // prefix is not the router's single source of truth violation
        // Sonar targets.
        assert!(
            found(concat!(
                "from fastapi import APIRouter, FastAPI\n",
                "\n",
                "router = APIRouter(prefix=\"/api\")\n",
                "app = FastAPI()\n",
                "app.include_router(router, prefix=\"/v1\")\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8413_ignores_unbound_and_non_router_arguments() {
        // The argument is not a bare name bound to one `APIRouter()` call.
        assert!(
            found(concat!(
                "from fastapi import APIRouter, FastAPI\n",
                "\n",
                "app = FastAPI()\n",
                "app.include_router(APIRouter(), prefix=\"/api\")\n",
                "\n",
                "def setup(router):\n",
                "    app.include_router(router, prefix=\"/api\")\n",
            ))
            .is_empty()
        );
    }
}
