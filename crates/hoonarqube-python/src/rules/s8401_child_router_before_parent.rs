use ruff_python_ast::{Expr, ExprCall};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, is_include_router, nth_or_keyword_argument};
use crate::support::{issue_at, to_pos};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8401";
const MESSAGE: &str = "Include child routers before registering the parent router.";

/// python:S8401 — `FastAPI` snapshots a router's path operations when the
/// router is passed to `include_router`; adding child routers to a parent
/// afterwards silently leaves the child's endpoints unregistered. Sonar
/// flags a `FastAPI|APIRouter.include_router` call whose receiver symbol was
/// already used as the `router` argument of an earlier `include_router`
/// call in the same function/lambda/module scope. The whole call anchors
/// the finding.
pub(crate) fn check_s8401_child_router_before_parent(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut registrations: Vec<(String, Option<TextRange>, u32)> = Vec::new();
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !is_include_router_call(&facts, call) {
            continue;
        }
        let line = to_pos(call.range().start(), index, source).line;
        let scope = facts.enclosing_scope(call.range());
        if let Expr::Name(receiver) = receiver_of(call)
            && registrations
                .iter()
                .any(|(name, registered_scope, registered_line)| {
                    *name == receiver.id.as_str()
                        && *registered_scope == scope
                        && *registered_line < line
                })
        {
            issues.push(issue_at(RULE_KEY, MESSAGE, call.range(), index, source));
        }
        if let Some(Expr::Name(argument)) = nth_or_keyword_argument(call, 0, "router") {
            registrations.push((argument.id.as_str().to_string(), scope, line));
        }
    }
    issues
}

fn is_include_router_call(facts: &WebFrameworkFacts<'_>, call: &ExprCall) -> bool {
    facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| is_include_router(&fqn))
}

fn receiver_of(call: &ExprCall) -> &Expr {
    match call.func.as_ref() {
        Expr::Attribute(attribute) => attribute.value.as_ref(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8401")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8401_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: `parent_router` is registered with
        // the app on line 10, then gains a child router on line 11 — the
        // whole `include_router` call anchors the finding.
        let ranges = found(concat!(
            "from fastapi import FastAPI, APIRouter\n",
            "\n",
            "app = FastAPI()\n",
            "parent_router = APIRouter()\n",
            "child_router = APIRouter()\n",
            "\n",
            "@child_router.get(\"/items\")\n",
            "def get_items():\n",
            "    return {\"items\": []}\n",
            "app.include_router(parent_router, prefix=\"/api\")\n",
            "parent_router.include_router(child_router)\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(11, 0));
        assert_eq!(ranges[0].end, pos(11, 42));
    }

    #[test]
    fn s8401_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI, APIRouter\n",
                "\n",
                "app = FastAPI()\n",
                "parent_router = APIRouter()\n",
                "child_router = APIRouter()\n",
                "\n",
                "@child_router.get(\"/items\")\n",
                "def get_items():\n",
                "    return {\"items\": []}\n",
                "parent_router.include_router(child_router)\n",
                "app.include_router(parent_router, prefix=\"/api\")\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8401_flags_deep_nesting_from_the_bottom_up() {
        // Sonar's multi-level example: both late child registrations flag.
        let ranges = found(concat!(
            "from fastapi import FastAPI, APIRouter\n",
            "\n",
            "app = FastAPI()\n",
            "api_router = APIRouter()\n",
            "v1_router = APIRouter()\n",
            "users_router = APIRouter()\n",
            "\n",
            "app.include_router(api_router)\n",
            "api_router.include_router(v1_router, prefix=\"/v1\")\n",
            "v1_router.include_router(users_router, prefix=\"/users\")\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(9, 0));
        assert_eq!(ranges[1].start, pos(10, 0));
    }

    #[test]
    fn s8401_ignores_unrelated_and_unbound_calls() {
        // `include_router` on a non-FastAPI receiver, a registration whose
        // argument is not a bare name, and a late include in a different
        // scope all stay silent.
        assert!(
            found(concat!(
                "from fastapi import FastAPI, APIRouter\n",
                "\n",
                "app = FastAPI()\n",
                "parent_router = APIRouter()\n",
                "other = object()\n",
                "other.include_router(parent_router)\n",
                "\n",
                "def setup():\n",
                "    parent_router.include_router(APIRouter())\n",
            ))
            .is_empty()
        );
    }
}
