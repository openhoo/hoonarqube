use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, exprs_textually_equal, is_fastapi_verb, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8409";
const MESSAGE: &str =
    "Remove this redundant \"response_model\" parameter; it duplicates the return type annotation.";

/// python:S8409 — `FastAPI` infers the response model from the handler's
/// return type annotation, so a route decorator `response_model=` that
/// repeats the same type is redundant. Sonar flags the whole
/// `response_model=<expr>` keyword argument when the decorator is a
/// `FastAPI`/`APIRouter` HTTP-verb route and the argument expression is
/// structurally equivalent to the return annotation; a different
/// `response_model` (the legitimate override case) and handlers without
/// a return annotation stay silent.
pub(crate) fn check_s8409_redundant_response_model(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        let Some(returns) = function.returns.as_deref() else {
            continue;
        };
        for decorator in &function.decorator_list {
            issues.extend(redundant_response_model_issues(
                &facts, decorator, returns, index, source,
            ));
        }
    }
    issues
}

/// Findings for one route decorator: each `response_model=` keyword
/// whose expression duplicates the return annotation.
fn redundant_response_model_issues(
    facts: &WebFrameworkFacts<'_>,
    decorator: &ruff_python_ast::Decorator,
    returns: &Expr,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Expr::Call(call) = &decorator.expression else {
        return issues;
    };
    if !facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| is_fastapi_verb(&fqn))
    {
        return issues;
    }
    for keyword in &call.arguments.keywords {
        if keyword.arg.as_deref() != Some("response_model") {
            continue;
        }
        if annotations_equivalent(&keyword.value, returns, source) {
            issues.push(issue_at(RULE_KEY, MESSAGE, keyword.range(), index, source));
        }
    }
    issues
}

/// Structural equality of two annotation expressions: Sonar's
/// `CheckUtils.areEquivalent` compares AST shapes, so `Item` matches
/// `Item` and `List[Item]` matches `List[Item]` while whitespace is
/// ignored.
fn annotations_equivalent(model: &Expr, returns: &Expr, source: &str) -> bool {
    exprs_textually_equal(model, returns, source)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8409")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8409_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: `response_model` repeating the
        // return annotation on every HTTP verb and on APIRouter.
        let ranges = found(concat!(
            "from typing import List, Optional\n",
            "from fastapi import FastAPI, APIRouter\n",
            "from pydantic import BaseModel\n",
            "\n",
            "app = FastAPI()\n",
            "router = APIRouter()\n",
            "\n",
            "class Item(BaseModel):\n",
            "    name: str\n",
            "\n",
            "@app.post(\"/items/\", response_model=Item)\n",
            "async def create_item(item: Item) -> Item:\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/{item_id}\", response_model=Item)\n",
            "def get_item(item_id: int) -> Item:\n",
            "    return fetch_item(item_id)\n",
            "\n",
            "@router.post(\"/items/\", response_model=Item)\n",
            "def create_item_router(item: Item) -> Item:\n",
            "    return item\n",
            "\n",
            "@app.get(\"/items/\", response_model=List[Item])\n",
            "def get_items() -> List[Item]:\n",
            "    return items\n",
            "\n",
            "@app.get(\"/item/{item_id}\", response_model=Optional[Item])\n",
            "def get_optional_item(item_id: int) -> Optional[Item]:\n",
            "    return maybe_item\n",
            "\n",
            "@app.post(\"/items/\", status_code=201, response_model=Item, tags=[\"items\"])\n",
            "def create_item_middle(item: Item) -> Item:\n",
            "    return item\n",
        ));
        assert_eq!(ranges.len(), 6);
        // `response_model=Item` on line 11: columns 21–39.
        assert_eq!(ranges[0].start, pos(11, 21));
        assert_eq!(ranges[0].end, pos(11, 40));
    }

    #[test]
    fn s8409_accepts_the_sonar_compliant_examples() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "from pydantic import BaseModel\n",
                "\n",
                "app = FastAPI()\n",
                "\n",
                "class UserPublic(BaseModel):\n",
                "    id: int\n",
                "\n",
                "class UserInternal(BaseModel):\n",
                "    id: int\n",
                "    password: str\n",
                "\n",
                "@app.post(\"/items/\")\n",
                "async def create_item_no_model(item: UserPublic) -> UserPublic:\n",
                "    return item\n",
                "\n",
                "@app.post(\"/items/\", response_model=UserPublic)\n",
                "def create_item_no_return_type_hint(item: UserPublic):\n",
                "    return item\n",
                "\n",
                "@app.get(\"/users/{user_id}\", response_model=UserPublic)\n",
                "def compliant_overriding_response_model(user_id: int) -> UserInternal:\n",
                "    return fetch_user_with_password(user_id)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8409_ignores_non_fastapi_decorators_and_missing_calls() {
        assert!(
            found(concat!(
                "from fastapi import FastAPI\n",
                "\n",
                "app = FastAPI()\n",
                "\n",
                "@some_other_decorator(\"/items/\", response_model=Item)\n",
                "def non_fastapi_endpoint(item: Item) -> Item:\n",
                "    return item\n",
                "\n",
                "@app.post\n",
                "def invalid_decorator() -> Item:\n",
                "    return item\n",
            ))
            .is_empty()
        );
    }
}
