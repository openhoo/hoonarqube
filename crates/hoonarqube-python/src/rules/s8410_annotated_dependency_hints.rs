use ruff_python_ast::{AnyParameterRef, Expr};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, is_fastapi_verb, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8410";
const MESSAGE: &str = "Use \"Annotated\" type hints for FastAPI dependency injection";

/// `FastAPI` parameter-marker factories Sonar recognizes in both the
/// old (default value) and new (`Annotated[...]` metadata) styles.
const DEPENDENCY_FUNCTION_FQNS: [&str; 16] = [
    "fastapi.param_functions.Depends",
    "fastapi.param_functions.Query",
    "fastapi.param_functions.Path",
    "fastapi.param_functions.Body",
    "fastapi.param_functions.Header",
    "fastapi.param_functions.Cookie",
    "fastapi.param_functions.Form",
    "fastapi.param_functions.File",
    "fastapi.Depends",
    "fastapi.Query",
    "fastapi.Path",
    "fastapi.Body",
    "fastapi.Header",
    "fastapi.Cookie",
    "fastapi.Form",
    "fastapi.File",
];

const ANNOTATED_FQNS: [&str; 2] = ["typing.Annotated", "typing_extensions.Annotated"];

/// python:S8410 — `FastAPI` recommends declaring dependencies as
/// `Annotated[T, Depends(...)]` metadata instead of `param = Depends(...)`
/// defaults. Sonar collects old-style parameters on `FastAPI` route
/// functions, then applies a file-local heuristic: findings are
/// suppressed when the file mixes both styles and at least 75% of the
/// styled parameters are old-style (fewer than three styled parameters
/// always report). A parameter whose annotation already wraps a
/// dependency call in `Annotated[...]` counts as new-style and is never
/// flagged, even when its default repeats the dependency call.
pub(crate) fn check_s8410_annotated_dependency_hints(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut pending: Vec<TextRange> = Vec::new();
    let mut annotated_style_count = 0usize;
    let mut old_style_count = 0usize;

    for function in &file_ctx.functions {
        if !has_fastapi_route_decorator(&facts, function) {
            continue;
        }
        for param in &function.parameters {
            if uses_annotated_dependency(&facts, param) {
                annotated_style_count += 1;
            } else if uses_old_dependency_default(&facts, param) {
                old_style_count += 1;
                pending.push(param.range());
            }
        }
    }

    let total = annotated_style_count + old_style_count;
    if total >= 3 && old_style_count * 4 >= total * 3 {
        return Vec::new();
    }
    pending
        .into_iter()
        .map(|range| issue_at(RULE_KEY, MESSAGE, range, index, source))
        .collect()
}

/// Any decorator is a `FastAPI`/`APIRouter` HTTP-verb route call.
fn has_fastapi_route_decorator(
    facts: &WebFrameworkFacts<'_>,
    function: &ruff_python_ast::StmtFunctionDef,
) -> bool {
    function.decorator_list.iter().any(|decorator| {
        let Expr::Call(call) = &decorator.expression else {
            return false;
        };
        facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| is_fastapi_verb(&fqn))
    })
}

/// The annotation is `Annotated[..., <dependency call>, ...]` — the
/// modern style. Only `typing.Annotated`/`typing_extensions.Annotated`
/// count, matching Sonar's type matcher and FQN fallback.
fn uses_annotated_dependency(facts: &WebFrameworkFacts<'_>, param: AnyParameterRef<'_>) -> bool {
    let Some(Expr::Subscript(subscript)) = param.annotation() else {
        return false;
    };
    if !is_annotated_object(facts, &subscript.value) {
        return false;
    }
    subscript_elements(&subscript.slice).iter().any(|element| {
        let Expr::Call(call) = element else {
            return false;
        };
        facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| DEPENDENCY_FUNCTION_FQNS.contains(&fqn.as_str()))
    })
}

/// The default value is a `FastAPI` dependency-marker call — the old
/// style. Parameters already using `Annotated[...]` with a dependency
/// are excluded by the caller ordering.
fn uses_old_dependency_default(facts: &WebFrameworkFacts<'_>, param: AnyParameterRef<'_>) -> bool {
    let Some(Expr::Call(call)) = param.default() else {
        return false;
    };
    facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| DEPENDENCY_FUNCTION_FQNS.contains(&fqn.as_str()))
}

fn is_annotated_object(facts: &WebFrameworkFacts<'_>, expr: &Expr) -> bool {
    if facts
        .expr_fqn(expr)
        .is_some_and(|fqn| ANNOTATED_FQNS.contains(&fqn.as_str()))
    {
        return true;
    }
    lexical_dotted_name(expr).is_some_and(|name| ANNOTATED_FQNS.contains(&name.as_str()))
}

/// The dotted spelling of a pure name/attribute chain (`t.Annotated`).
fn lexical_dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attribute) => Some(format!(
            "{}.{}",
            lexical_dotted_name(&attribute.value)?,
            attribute.attr.as_str()
        )),
        _ => None,
    }
}

/// Elements of a subscript slice: `X[a]` → `[a]`, `X[a, b]` → `[a, b]`.
fn subscript_elements(slice: &Expr) -> Vec<&Expr> {
    match slice {
        Expr::Tuple(tuple) => tuple.elts.iter().collect(),
        expr => vec![expr],
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan(source), "python:S8410")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    const PRELUDE: &str = concat!(
        "from typing import Annotated\n",
        "from fastapi import Depends, FastAPI, Query, Path, Body, Header, Cookie, Form, File\n",
        "from fastapi import APIRouter\n",
        "\n",
        "app = FastAPI()\n",
        "router = APIRouter()\n",
        "\n",
        "def get_db():\n",
        "    return \"database_connection\"\n",
        "\n",
    );

    #[test]
    fn s8410_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: every dependency-marker factory
        // as a parameter default on app and router routes.
        let ranges = found(
            &[
                PRELUDE,
                concat!(
                    "@app.get(\"/items/\")\n",
                    "def read_items(db = Depends(get_db)):\n",
                    "    return {\"db\": db}\n",
                    "\n",
                    "@app.get(\"/search/\")\n",
                    "def search_items(q: str = Query(None, max_length=50)):\n",
                    "    return {\"query\": q}\n",
                    "\n",
                    "@app.get(\"/items/{item_id}\")\n",
                    "def read_item(item_id: int = Path(gt=0)):\n",
                    "    return {\"item_id\": item_id}\n",
                    "\n",
                    "@app.post(\"/items/\")\n",
                    "def create_item(item: dict = Body()):\n",
                    "    return item\n",
                    "\n",
                    "@app.get(\"/items/\")\n",
                    "def read_items2(x_token: str = Header()):\n",
                    "    return {\"X-Token\": x_token}\n",
                    "\n",
                    "@app.get(\"/items/\")\n",
                    "def read_items3(session: str = Cookie()):\n",
                    "    return {\"session\": session}\n",
                    "\n",
                    "@router.get(\"/items/\")\n",
                    "def read_items4(db = Depends(get_db)):\n",
                    "    return {\"db\": db}\n",
                    "\n",
                    "@app.post(\"/form/\")\n",
                    "def form(name: str = Form(...)):\n",
                    "    pass\n",
                    "\n",
                    "@app.post(\"/upload/\")\n",
                    "def upload(file = File(...)):\n",
                    "    pass\n",
                    "\n",
                    "@app.get(\"/mixed/\")\n",
                    "def mixed(\n",
                    "    a: Annotated[str, Depends(get_db)],\n",
                    "    b: Annotated[str, Depends(get_db)],\n",
                    "    c: Annotated[str, Depends(get_db)],\n",
                    "    d: Annotated[str, Depends(get_db)],\n",
                    "):\n",
                    "    return {}\n",
                ),
            ]
            .concat(),
        );
        // 9 old-style + 4 annotated-style = 0.69 old ratio → reported.
        assert_eq!(ranges.len(), 9);
        // `db = Depends(get_db)` on line 12: columns 15–35.
        assert_eq!(ranges[0].start, pos(12, 15));
        assert_eq!(ranges[0].end, pos(12, 35));
    }

    #[test]
    fn s8410_accepts_the_sonar_compliant_examples() {
        assert!(
            found(&[PRELUDE, concat!(
                "@app.get(\"/items/\")\n",
                "def read_items(db: Annotated[str, Depends(get_db)]):\n",
                "    return {\"db\": db}\n",
                "\n",
                "@app.get(\"/search/\")\n",
                "def search_items(q: Annotated[str | None, Query(max_length=50)] = None):\n",
                "    return {\"query\": q}\n",
                "\n",
                "@app.get(\"/items/{item_id}\")\n",
                "def read_item(item_id: Annotated[int, Path(gt=0)]):\n",
                "    return {\"item_id\": item_id}\n",
                "\n",
                "@app.get(\"/items/\")\n",
                "def read_items2(skip: int = 0, limit: int = 10):\n",
                "    return {\"skip\": skip, \"limit\": limit}\n",
                "\n",
                "@app.get(\"/items/\")\n",
                "def read_items3(db: Annotated[str, Depends(get_db)] = Depends(get_db)):\n",
                "    return {\"db\": db}\n",
                "\n",
                "def not_a_route_handler(db = Depends(get_db)):\n",
                "    return {\"db\": db}\n",
            )].concat())
            .is_empty()
        );
    }

    #[test]
    fn s8410_annotated_spellings_count_as_new_style() {
        // typing.Annotated, aliased `import typing as t`, and
        // typing_extensions aliases all satisfy the matcher.
        assert!(
            found(concat!(
                "import typing\n",
                "import typing as t\n",
                "from typing_extensions import Annotated as Ann\n",
                "from fastapi import Depends, FastAPI\n",
                "\n",
                "app = FastAPI()\n",
                "\n",
                "def get_db():\n",
                "    return \"db\"\n",
                "\n",
                "@app.get(\"/a/\")\n",
                "def a(db: typing.Annotated[str, Depends(get_db)] = Depends(get_db)):\n",
                "    return db\n",
                "\n",
                "@app.get(\"/b/\")\n",
                "def b(db: t.Annotated[str, Depends(get_db)] = Depends(get_db)):\n",
                "    return db\n",
                "\n",
                "@app.get(\"/c/\")\n",
                "def c(db: Ann[str, Depends(get_db)] = Depends(get_db)):\n",
                "    return db\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8410_file_local_heuristic_suppresses_old_style_dominant_files() {
        // 3 old-style + 1 annotated-style = 0.75 old ratio → suppressed.
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "@app.get(\"/items/\")\n",
                        "def read_items(\n",
                        "    db = Depends(get_db),\n",
                        "    limit: int = Query(10),\n",
                        "    page: int = Query(1),\n",
                        "    search: Annotated[str | None, Query(max_length=50)] = None,\n",
                        "):\n",
                        "    return {}\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }

    #[test]
    fn s8410_file_local_heuristic_reports_annotated_dominant_files() {
        // 1 old-style + 2 annotated-style = 0.33 old ratio → reported.
        let ranges = found(
            &[
                PRELUDE,
                concat!(
                    "@app.get(\"/items/\")\n",
                    "def read_items(\n",
                    "    db: Annotated[str, Depends(get_db)],\n",
                    "    search: Annotated[str | None, Query(max_length=50)] = None,\n",
                    "    limit: int = Query(10),\n",
                    "):\n",
                    "    return {}\n",
                ),
            ]
            .concat(),
        );
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(15, 4));
    }

    #[test]
    fn s8410_file_local_heuristic_reports_too_small_samples() {
        // Fewer than three styled parameters always report.
        let ranges = found(
            &[
                PRELUDE,
                concat!(
                    "@app.get(\"/items/\")\n",
                    "def read_items(\n",
                    "    db = Depends(get_db),\n",
                    "    session = Depends(get_db),\n",
                    "):\n",
                    "    return {}\n",
                ),
            ]
            .concat(),
        );
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn s8410_ignores_non_dependency_defaults_and_non_route_functions() {
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "some_value = Query(None)\n",
                        "\n",
                        "def some_function():\n",
                        "    return \"value\"\n",
                        "\n",
                        "@app.get(\"/items/\")\n",
                        "def read_items(q = some_value, value = some_function()):\n",
                        "    return {\"q\": q}\n",
                        "\n",
                        "def my_decorator(func):\n",
                        "    return func\n",
                        "\n",
                        "@my_decorator\n",
                        "def not_a_route(q = Query(None)):\n",
                        "    return {\"q\": q}\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }
}
