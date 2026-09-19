use ruff_python_ast::{AnyParameterRef, Expr, ExprCall, StmtClassDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::engine::file_context::FileContext;
use crate::support::{WebFrameworkFacts, fqn_is_member, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8389";
const MESSAGE_BODY_WITH_FILE: &str = "Use \"Form()\" instead of \"Body()\" when handling file uploads; \"Body()\" expects JSON, which is incompatible with multipart/form-data.";
const MESSAGE_DEPENDS_WITH_FILE: &str = "Use \"Form()\" with Pydantic validators instead of \"Depends()\" for file upload endpoints; query parameters may expose sensitive data in URLs.";

/// Route verbs that can carry a request body.
const BODY_VERBS: [&str; 4] = ["post", "put", "patch", "delete"];

const FILE_FQNS: [&str; 2] = ["fastapi.param_functions.File", "fastapi.File"];
const BODY_FQNS: [&str; 2] = ["fastapi.param_functions.Body", "fastapi.Body"];
const DEPENDS_FQNS: [&str; 2] = ["fastapi.param_functions.Depends", "fastapi.Depends"];
const UPLOAD_FILE_FQNS: [&str; 4] = [
    "fastapi.UploadFile",
    "fastapi.datastructures.UploadFile",
    "starlette.UploadFile",
    "starlette.datastructures.UploadFile",
];
const BASE_MODEL_FQNS: [&str; 2] = ["pydantic.BaseModel", "pydantic.main.BaseModel"];

/// python:S8389 — a `FastAPI` endpoint that accepts file uploads receives
/// `multipart/form-data`, so structured data must come through `Form()`
/// fields, not JSON `Body()` parameters or `Depends()` on a Pydantic
/// model (which leaks data into query parameters). Sonar flags each
/// `Body()`-defaulted parameter and each `Depends()`-defaulted
/// parameter whose dependency or annotation is a Pydantic model, but
/// only on `post`/`put`/`patch`/`delete` routes that also declare a
/// file parameter (`File()` default or an `UploadFile` annotation,
/// including inside `List[...]`/`Optional[...]`).
pub(crate) fn check_s8389_file_upload_form(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = WebFrameworkFacts::build(file_ctx);
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        let has_body_route = function.decorator_list.iter().any(|decorator| {
            let Expr::Call(call) = &decorator.expression else {
                return false;
            };
            facts.expr_fqn(&call.func).is_some_and(|fqn| {
                BODY_VERBS.iter().any(|verb| {
                    fqn_is_member(
                        &fqn,
                        &["fastapi.applications.FastAPI", "fastapi.routing.APIRouter"],
                        verb,
                    )
                })
            })
        });
        if !has_body_route {
            continue;
        }
        let parameters = &function.parameters;
        if !parameters.iter().any(|param| is_file_param(&facts, param)) {
            continue;
        }
        for param in parameters {
            if has_body_default(&facts, param) {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE_BODY_WITH_FILE,
                    param.range(),
                    index,
                    source,
                ));
            }
            if has_depends_on_pydantic(&facts, param) {
                issues.push(issue_at(
                    RULE_KEY,
                    MESSAGE_DEPENDS_WITH_FILE,
                    param.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

/// A parameter is a file upload when its default is `File(...)` or its
/// annotation is `UploadFile` (possibly inside a subscription such as
/// `List[UploadFile]` or `Optional[UploadFile]`).
fn is_file_param(facts: &WebFrameworkFacts<'_>, param: AnyParameterRef<'_>) -> bool {
    if let Some(Expr::Call(call)) = param.default()
        && facts
            .expr_fqn(&call.func)
            .is_some_and(|fqn| FILE_FQNS.contains(&fqn.as_str()))
    {
        return true;
    }
    let Some(annotation) = param.annotation() else {
        return false;
    };
    if is_upload_file(facts, annotation, param.range()) {
        return true;
    }
    if let Expr::Subscript(subscript) = annotation {
        return subscript_elements(&subscript.slice)
            .iter()
            .any(|element| is_upload_file(facts, element, param.range()));
    }
    false
}

/// `Body(...)` as the parameter default.
fn has_body_default(facts: &WebFrameworkFacts<'_>, param: AnyParameterRef<'_>) -> bool {
    let Some(Expr::Call(call)) = param.default() else {
        return false;
    };
    facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| BODY_FQNS.contains(&fqn.as_str()))
}

/// `Depends(...)` as the parameter default where the dependency target
/// (first regular argument) or — without one — the parameter annotation
/// is a Pydantic model.
fn has_depends_on_pydantic(facts: &WebFrameworkFacts<'_>, param: AnyParameterRef<'_>) -> bool {
    let Some(Expr::Call(call)) = param.default() else {
        return false;
    };
    if !facts
        .expr_fqn(&call.func)
        .is_some_and(|fqn| DEPENDS_FQNS.contains(&fqn.as_str()))
    {
        return false;
    }
    if let Some(first) = first_regular_argument(call) {
        return is_pydantic_model(facts, first, param.range());
    }
    param
        .annotation()
        .is_some_and(|annotation| is_pydantic_model(facts, annotation, param.range()))
}

/// The first positional or keyword argument of `call`; `*args` and
/// `**kwargs` do not count (Sonar's `RegularArgument`).
fn first_regular_argument(call: &ExprCall) -> Option<&Expr> {
    call.arguments
        .iter_source_order()
        .next()
        .and_then(|entry| match entry {
            ruff_python_ast::ArgOrKeyword::Arg(expr) if !expr.is_starred_expr() => Some(expr),
            ruff_python_ast::ArgOrKeyword::Keyword(keyword) if keyword.arg.is_some() => {
                Some(&keyword.value)
            }
            _ => None,
        })
}

/// `expr` names `UploadFile` or a same-file class deriving from it.
fn is_upload_file(
    facts: &WebFrameworkFacts<'_>,
    expr: &Expr,
    at: ruff_text_size::TextRange,
) -> bool {
    if facts
        .expr_fqn(expr)
        .is_some_and(|fqn| UPLOAD_FILE_FQNS.contains(&fqn.as_str()))
    {
        return true;
    }
    class_extends(facts, expr, at, &UPLOAD_FILE_FQNS, 0)
}

/// `expr` names `pydantic.BaseModel` or a same-file class deriving
/// from it.
fn is_pydantic_model(
    facts: &WebFrameworkFacts<'_>,
    expr: &Expr,
    at: ruff_text_size::TextRange,
) -> bool {
    if facts
        .expr_fqn(expr)
        .is_some_and(|fqn| BASE_MODEL_FQNS.contains(&fqn.as_str()))
    {
        return true;
    }
    class_extends(facts, expr, at, &BASE_MODEL_FQNS, 0)
}

/// Whether `expr` resolves to a same-file class whose base list
/// transitively contains one of `base_fqns`.
fn class_extends(
    facts: &WebFrameworkFacts<'_>,
    expr: &Expr,
    at: ruff_text_size::TextRange,
    base_fqns: &[&str],
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(class) = facts.resolve_class_def(expr, at) else {
        return false;
    };
    class_has_base(facts, class, base_fqns, depth)
}

fn class_has_base(
    facts: &WebFrameworkFacts<'_>,
    class: &StmtClassDef,
    base_fqns: &[&str],
    depth: u32,
) -> bool {
    let Some(arguments) = class.arguments.as_deref() else {
        return false;
    };
    arguments.args.iter().any(|base| {
        facts
            .expr_fqn(base)
            .is_some_and(|fqn| base_fqns.contains(&fqn.as_str()))
            || class_extends(facts, base, class.range(), base_fqns, depth + 1)
    })
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

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8389")
            .into_iter()
            .cloned()
            .collect()
    }

    const PRELUDE: &str = concat!(
        "from typing import List, Optional\n",
        "from fastapi import FastAPI, APIRouter, Body, Depends, File, Form, UploadFile\n",
        "from pydantic import BaseModel\n",
        "from starlette.datastructures import UploadFile as StarletteUploadFile\n",
        "\n",
        "app = FastAPI()\n",
        "router = APIRouter()\n",
        "\n",
        "class Base(BaseModel):\n",
        "    name: str\n",
        "\n",
        "class PolicyData(BaseModel):\n",
        "    policy_id: str\n",
        "\n",
        "def get_current_user():\n",
        "    return {\"user\": \"test\"}\n",
        "\n",
    );

    #[test]
    fn s8389_flags_the_sonar_noncompliant_examples() {
        // Sonar's Noncompliant examples: Body()/Depends() parameters on
        // file-upload routes across the four body verbs.
        let issues = found(&[PRELUDE, concat!(
            "@router.post(\"/upload\")\n",
            "async def upload_with_body(\n",
            "    country_id: str = Body(...),\n",
            "    policy_details: List[dict] = Body(...),\n",
            "    files: List[UploadFile] = File(...)\n",
            "):\n",
            "    return {\"status\": \"ok\"}\n",
            "\n",
            "@app.post(\"/submit\")\n",
            "def submit_with_depends(\n",
            "    base: Base = Depends(),\n",
            "    files: List[UploadFile] = File(...)\n",
            "):\n",
            "    pass\n",
            "\n",
            "@router.post(\"/submit2\")\n",
            "async def submit_explicit_depends(\n",
            "    data: PolicyData = Depends(PolicyData),\n",
            "    file: UploadFile = File(...)\n",
            "):\n",
            "    pass\n",
            "\n",
            "@app.post(\"/optional\")\n",
            "def optional_file(\n",
            "    data: str = Body(...),\n",
            "    file: Optional[UploadFile] = File(None)\n",
            "):\n",
            "    pass\n",
            "\n",
            "@app.put(\"/update\")\n",
            "def put_endpoint(data: str = Body(...), file: UploadFile = File(...)): pass\n",
            "\n",
            "@app.patch(\"/patch\")\n",
            "def patch_endpoint(data: str = Body(...), file: UploadFile = File(...)): pass\n",
            "\n",
            "@app.delete(\"/delete-with-file\")\n",
            "def delete_endpoint(data: str = Body(...), file: UploadFile = File(...)): pass\n",
            "\n",
            "@app.post(\"/type-annotation-only\")\n",
            "def type_annotation_file_without_default_value(\n",
            "    file: UploadFile,\n",
            "    data: str = Body(...)\n",
            "):\n",
            "    pass\n",
            "\n",
            "@app.post(\"/starlette-file\")\n",
            "def starlette_upload(\n",
            "    data: str = Body(...),\n",
            "    file: StarletteUploadFile = File(...)\n",
            "):\n",
            "    pass\n",
            "\n",
            "@app.post(\"/empty-depends-with-annotation\")\n",
            "def empty_depends_with_annotation(\n",
            "    base: Base = Depends(),\n",
            "    file: UploadFile = File(...)\n",
            "):\n",
            "    pass\n",
        )].concat());
        assert_eq!(issues.len(), 11);
        assert!(
            issues[0]
                .message
                .contains("\"Form()\" instead of \"Body()\"")
        );
        assert!(issues[2].message.contains("\"Depends()\""));
        // First finding anchors the whole `country_id: str = Body(...)` parameter.
        assert_eq!(issues[0].range.start, pos(20, 4));
    }

    #[test]
    fn s8389_accepts_the_sonar_compliant_examples() {
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "@router.post(\"/upload-compliant\")\n",
                        "async def compliant_upload(\n",
                        "    name: str = Form(...),\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "@app.post(\"/json-only\")\n",
                        "def json_endpoint(\n",
                        "    data: PolicyData = Body(...),\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "@router.post(\"/no-file\")\n",
                        "def no_file_depends(\n",
                        "    base: Base = Depends(),\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "@app.post(\"/depends-function\")\n",
                        "def depends_with_function(\n",
                        "    user = Depends(get_current_user),\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "def parse_config(data: str = Form(...)) -> PolicyData:\n",
                        "    return PolicyData.model_validate_json(data)\n",
                        "\n",
                        "@app.post(\"/data\")\n",
                        "async def upload_data(\n",
                        "    config: PolicyData = Depends(parse_config),\n",
                        "    csv_file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "@app.post(\"/depends-no-annotation\")\n",
                        "def depends_no_annotation(\n",
                        "    dep = Depends(get_current_user),\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "dependency_args = [get_current_user]\n",
                        "\n",
                        "@app.post(\"/depends-unpacking-arg\")\n",
                        "def depends_unpacking_arg(\n",
                        "    dep = Depends(*dependency_args),\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "@app.post(\"/file-only\")\n",
                        "def file_only_endpoint(\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                        "\n",
                        "def regular_function(\n",
                        "    data: str = Body(...),\n",
                        "    file: UploadFile = File(...)\n",
                        "):\n",
                        "    pass\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }

    #[test]
    fn s8389_ignores_get_routes() {
        // Sonar only matches the body-carrying verbs.
        assert!(
            found(
                &[
                    PRELUDE,
                    concat!(
                        "@app.get(\"/download\")\n",
                        "def get_endpoint(data: str = Body(...), file: UploadFile = File(...)):\n",
                        "    pass\n",
                    )
                ]
                .concat()
            )
            .is_empty()
        );
    }
}
