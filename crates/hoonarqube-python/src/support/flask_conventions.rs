// --- Flask/FastAPI conventions
//
// Lightweight provenance tracking for the web-framework rule family
// (python:S6863, S8370, S8371, S8374, S8375, S8385, S8400). `WebBindings`
// resolves names and expressions to framework identities — Flask/FastAPI
// application instances, blueprints, the `flask.request` proxy, view and
// response classes, and file-like objects — from import statements, plain
// assignments, and local class bases. This is not a type checker: it mirrors
// the reference checks' FQN matchers closely enough to keep the same
// trigger shapes without guessing from a method's final spelling.

use crate::support::{collect_target_names, named_parameters, stmt_store_names};
use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_python_parser::Parsed;
use std::collections::HashMap;

/// Identity of a name or expression for the web-framework rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebBinding {
    /// No provenance (or an explicitly unknown local binding).
    Unknown,
    /// `flask` (or `flask.app`) module object.
    FlaskModule,
    /// `flask.blueprints` module object.
    FlaskBlueprintsModule,
    /// `flask.globals` module object.
    FlaskGlobalsModule,
    /// `flask.helpers` module object.
    FlaskHelpersModule,
    /// `flask.json` module object.
    FlaskJsonModule,
    /// `flask.templating` module object.
    FlaskTemplatingModule,
    /// `flask.views` module object.
    FlaskViewsModule,
    /// `flask.wrappers` module object.
    FlaskWrappersModule,
    /// The `flask.Flask` class object.
    FlaskClass,
    /// A `Flask(...)` application instance.
    FlaskApp,
    /// The `flask.Blueprint` class object.
    FlaskBlueprintClass,
    /// A `Blueprint(...)` instance.
    FlaskBlueprint,
    /// The `flask.request` proxy (a `flask.wrappers.Request`).
    FlaskRequest,
    /// The `flask.wrappers.Request` class object.
    FlaskRequestClass,
    /// The `flask.wrappers.Response` class object.
    FlaskResponseClass,
    /// A `flask.wrappers.Response` instance (`Response(...)`,
    /// `make_response(...)`, `jsonify(...)`).
    FlaskResponse,
    /// `flask.make_response`.
    FlaskMakeResponse,
    /// `flask.json.jsonify` (also re-exported as `flask.jsonify`).
    FlaskJsonify,
    /// `flask.templating.render_template`.
    FlaskRenderTemplate,
    /// `flask.templating.render_template_string`.
    FlaskRenderTemplateString,
    /// `flask.send_file`.
    FlaskSendFile,
    /// `flask.views.View` or `flask.views.MethodView` class object, or a local
    /// subclass of one.
    FlaskViewClass,
    /// `app.errorhandler` / `bp.errorhandler` / `bp.app_errorhandler` bound
    /// method (the error-handler registrar).
    FlaskErrorHandler,
    /// `app.route` / `bp.route` bound method.
    FlaskRoute,
    /// `app.preprocess_request` bound method.
    FlaskPreprocessRequest,
    /// A `werkzeug.datastructures.Headers` instance (`request.headers`,
    /// `response.headers`).
    WerkzeugHeaders,
    /// `fastapi` (or `fastapi.applications`) module object.
    FastApiModule,
    /// `fastapi.responses` or `starlette.responses` module object.
    FastApiResponsesModule,
    /// `starlette` module object.
    StarletteModule,
    /// The `fastapi.FastAPI` class object.
    FastApiClass,
    /// A `FastAPI(...)` application instance.
    FastApiApp,
    /// A `fastapi`/`starlette.responses` `*Response` class object
    /// (`Response`, `JSONResponse`, `PlainTextResponse`, ...).
    FastApiResponseClass,
    /// `app.get`/`post`/`put`/`delete`/`patch`/`options`/`head`/`trace` bound
    /// method on a `FastAPI` application.
    FastApiRouteMethod,
    /// `io` module object.
    IoModule,
    /// `tempfile` module object.
    TempfileModule,
    /// `codecs` module object.
    CodecsModule,
    /// `gzip`/`bz2`/`lzma` module object.
    CompressedIoModule,
    /// `os` module object.
    OsModule,
    /// `pathlib` module object.
    PathlibModule,
    /// The `pathlib.Path` class object.
    PathClass,
    /// A `pathlib.Path(...)` instance.
    PathInstance,
    /// A callable returning a file-like object (`open`, `io.open`,
    /// `io.BytesIO`, `tempfile.TemporaryFile`, `gzip.open`, `os.fdopen`, ...).
    FileLikeFactory,
    /// A file-like object (`typing.IO` instance in the reference).
    FileLikeObject,
}

/// Per-file framework bindings: the module-level name map plus the
/// resolution tables. Function/class scope maps are derived on demand via
/// [`WebBindings::function_scope`]/[`WebBindings::class_scope`].
pub(crate) struct WebBindings {
    module: HashMap<String, WebBinding>,
}

impl WebBindings {
    /// Builds the module-level binding map from imports, assignments, and
    /// class definitions in source order.
    pub(crate) fn build(parsed: &Parsed<ModModule>) -> Self {
        let mut facts = Self {
            module: HashMap::new(),
        };
        let mut module = HashMap::new();
        record_scope(&mut module, &[], parsed.syntax().body.as_slice());
        facts.module = module;
        facts
    }

    /// The module-level binding map, for use as the outermost scope.
    pub(crate) fn module_scope(&self) -> &HashMap<String, WebBinding> {
        &self.module
    }
}

/// Bindings visible directly inside `function`'s body: parameters plus
/// the body's own sequential bindings. `outers` is the enclosing scope
/// chain, outermost first (module scope last element conventionally).
pub(crate) fn function_scope(
    function: &StmtFunctionDef,
    outers: &[&HashMap<String, WebBinding>],
) -> HashMap<String, WebBinding> {
    let mut map = HashMap::new();
    for parameter in named_parameters(&function.parameters) {
        map.insert(
            parameter.parameter.name.as_str().to_string(),
            WebBinding::Unknown,
        );
    }
    for parameter in [
        function.parameters.vararg.as_deref(),
        function.parameters.kwarg.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        map.insert(parameter.name.as_str().to_string(), WebBinding::Unknown);
    }
    record_scope(&mut map, outers, &function.body);
    map
}

/// Bindings visible directly inside `class`'s body (decorators and
/// attribute assignments are evaluated in the class scope).
pub(crate) fn class_scope(
    class: &StmtClassDef,
    outers: &[&HashMap<String, WebBinding>],
) -> HashMap<String, WebBinding> {
    let mut map = HashMap::new();
    record_scope(&mut map, outers, &class.body);
    map
}

/// Resolves an expression's framework identity against `scopes`
/// (outermost first): names, attribute chains, and constructor calls.
pub(crate) fn expr_in(expr: &Expr, scopes: &[&HashMap<String, WebBinding>]) -> WebBinding {
    expr_scoped(
        expr,
        scopes.last().copied(),
        &scopes[..scopes.len().saturating_sub(1)],
    )
}

fn name_scoped(
    name: &str,
    map: Option<&HashMap<String, WebBinding>>,
    outers: &[&HashMap<String, WebBinding>],
) -> WebBinding {
    if let Some(binding) = map.and_then(|map| map.get(name)) {
        return *binding;
    }
    for outer in outers.iter().rev() {
        if let Some(binding) = outer.get(name) {
            return *binding;
        }
    }
    fallback_binding(name)
}

fn expr_scoped(
    expr: &Expr,
    map: Option<&HashMap<String, WebBinding>>,
    outers: &[&HashMap<String, WebBinding>],
) -> WebBinding {
    match expr {
        Expr::Name(name) => name_scoped(name.id.as_str(), map, outers),
        Expr::Attribute(attribute) => {
            let base = expr_scoped(&attribute.value, map, outers);
            attribute_binding(base, attribute.attr.as_str())
        }
        Expr::Call(call) => call_result(expr_scoped(&call.func, map, outers)),
        Expr::Await(await_expr) => expr_scoped(&await_expr.value, map, outers),
        Expr::Named(named) => expr_scoped(&named.value, map, outers),
        _ => WebBinding::Unknown,
    }
}

/// Visits every statement with the scope chain its expressions see:
/// `scopes` is ordered outermost→innermost, each entry tagged `true` when it
/// is a class-body map. A `FunctionDef`/`ClassDef` statement itself is
/// visited with the enclosing chain (decorators and bases are evaluated
/// there); its body is then walked with the appropriate child map appended —
/// function bodies additionally drop enclosing class frames, matching
/// Python's lexical scoping.
pub(crate) fn visit_scoped_stmts<'a>(
    stmts: &'a [Stmt],
    module: &HashMap<String, WebBinding>,
    visit: &mut impl FnMut(&'a Stmt, &[(bool, &HashMap<String, WebBinding>)]),
) {
    visit_scoped_stmts_with_chain(stmts, vec![(false, module.clone())], visit);
}

/// [`visit_scoped_stmts`] starting from an explicit scope chain, for rules
/// that re-enter a nested suite (for example a route function's body) with
pub(crate) fn visit_scoped_stmts_with_chain<'a>(
    stmts: &'a [Stmt],
    chain: Vec<(bool, HashMap<String, WebBinding>)>,
    visit: &mut impl FnMut(&'a Stmt, &[(bool, &HashMap<String, WebBinding>)]),
) {
    fn walk<'a>(
        stmts: &'a [Stmt],
        chain: &mut Vec<(bool, HashMap<String, WebBinding>)>,
        visit: &mut impl FnMut(&'a Stmt, &[(bool, &HashMap<String, WebBinding>)]),
    ) {
        for stmt in stmts {
            {
                let refs: Vec<(bool, &HashMap<String, WebBinding>)> = chain
                    .iter()
                    .map(|(is_class, map)| (*is_class, map))
                    .collect();
                visit(stmt, &refs);
            }
            match stmt {
                Stmt::FunctionDef(function) => {
                    let outer_refs: Vec<&HashMap<String, WebBinding>> = chain
                        .iter()
                        .filter(|(is_class, _)| !*is_class)
                        .map(|(_, map)| map)
                        .collect();
                    let function_map = function_scope(function, &outer_refs);
                    let mut body_chain: Vec<(bool, HashMap<String, WebBinding>)> = chain
                        .iter()
                        .filter(|(is_class, _)| !*is_class)
                        .cloned()
                        .collect();
                    body_chain.push((false, function_map));
                    walk(&function.body, &mut body_chain, visit);
                }
                Stmt::ClassDef(class) => {
                    let outer_refs: Vec<&HashMap<String, WebBinding>> =
                        chain.iter().map(|(_, map)| map).collect();
                    let class_map = class_scope(class, &outer_refs);
                    chain.push((true, class_map));
                    walk(&class.body, chain, visit);
                    chain.pop();
                }
                _ => {
                    for body in crate::support::child_bodies(stmt) {
                        walk(body, chain, visit);
                    }
                }
            }
        }
    }
    let mut chain = chain;
    walk(stmts, &mut chain, visit);
}

/// Scope-chain view without class markers, for rules that resolve
/// expressions in the chain a statement sees.
pub(crate) fn scope_maps<'a>(
    scopes: &[(bool, &'a HashMap<String, WebBinding>)],
) -> Vec<&'a HashMap<String, WebBinding>> {
    scopes.iter().map(|(_, map)| *map).collect()
}

/// Scope chain for expressions inside a function body: the enclosing
/// non-class maps plus the function's own map.
pub(crate) fn body_scopes<'a>(
    decorator_scopes: &[(bool, &'a HashMap<String, WebBinding>)],
    function_map: &'a HashMap<String, WebBinding>,
) -> Vec<&'a HashMap<String, WebBinding>> {
    let mut scopes: Vec<&HashMap<String, WebBinding>> = decorator_scopes
        .iter()
        .filter(|(is_class, _)| !*is_class)
        .map(|(_, map)| *map)
        .collect();
    scopes.push(function_map);
    scopes
}

/// Records one scope's sequential bindings into `map`; nested `def`/`class`
/// bodies are separate scopes and are not entered. `outers` (outermost
/// first) resolves right-hand-side identities.
fn record_scope(
    map: &mut HashMap<String, WebBinding>,
    outers: &[&HashMap<String, WebBinding>],
    stmts: &[Stmt],
) {
    for stmt in stmts {
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    let local = alias.asname.as_deref().map_or_else(
                        || {
                            alias
                                .name
                                .as_str()
                                .split('.')
                                .next()
                                .unwrap_or("")
                                .to_string()
                        },
                        str::to_string,
                    );
                    let module = if alias.asname.is_some() {
                        alias.name.as_str()
                    } else {
                        alias.name.as_str().split('.').next().unwrap_or("")
                    };
                    map.insert(local, module_binding(module));
                }
            }
            Stmt::ImportFrom(import) => {
                let module = import
                    .module
                    .as_ref()
                    .filter(|_| import.level == 0)
                    .map(ruff_python_ast::Identifier::as_str);
                for alias in &import.names {
                    let local = alias
                        .asname
                        .as_deref()
                        .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
                    map.insert(local, from_import_binding(module, alias.name.as_str()));
                }
            }
            Stmt::Assign(assign) => {
                let value = expr_during_record(&assign.value, map, outers);
                for target in &assign.targets {
                    bind_target(map, target, value);
                }
            }
            Stmt::AnnAssign(assign) => {
                let value = assign
                    .value
                    .as_deref()
                    .map_or(WebBinding::Unknown, |value| {
                        expr_during_record(value, map, outers)
                    });
                bind_target(map, &assign.target, value);
            }
            Stmt::ClassDef(class) => {
                let base = class
                    .arguments
                    .as_ref()
                    .and_then(|arguments| {
                        arguments.args.iter().find_map(|base| {
                            let binding = expr_during_record(base, map, outers);
                            (binding != WebBinding::Unknown).then_some(binding)
                        })
                    })
                    .unwrap_or(WebBinding::Unknown);
                map.insert(class.name.as_str().to_string(), base);
            }
            _ => {
                for name in stmt_store_names(stmt) {
                    map.insert(name, WebBinding::Unknown);
                }
            }
        }
    }
}

/// Identity resolution while a scope map is still being recorded.
fn expr_during_record(
    expr: &Expr,
    map: &HashMap<String, WebBinding>,
    outers: &[&HashMap<String, WebBinding>],
) -> WebBinding {
    match expr {
        Expr::Name(name) => name_during_record(name.id.as_str(), map, outers),
        Expr::Attribute(attribute) => {
            let base = expr_during_record(&attribute.value, map, outers);
            attribute_binding(base, attribute.attr.as_str())
        }
        Expr::Call(call) => call_result(expr_during_record(&call.func, map, outers)),
        Expr::Await(await_expr) => expr_during_record(&await_expr.value, map, outers),
        Expr::Named(named) => expr_during_record(&named.value, map, outers),
        _ => WebBinding::Unknown,
    }
}

fn name_during_record(
    name: &str,
    map: &HashMap<String, WebBinding>,
    outers: &[&HashMap<String, WebBinding>],
) -> WebBinding {
    if let Some(binding) = map.get(name) {
        return *binding;
    }
    for outer in outers.iter().rev() {
        if let Some(binding) = outer.get(name) {
            return *binding;
        }
    }
    fallback_binding(name)
}

/// Binds an assignment target: a plain `name` keeps the value's identity;
/// tuple/list targets bind every element `Unknown` (element-wise shapes are
/// not tracked).
fn bind_target(map: &mut HashMap<String, WebBinding>, target: &Expr, value: WebBinding) {
    if let Expr::Name(name) = target {
        map.insert(name.id.as_str().to_string(), value);
        return;
    }
    let mut names = Vec::new();
    collect_target_names(target, &mut names);
    for name in names {
        map.insert(name, WebBinding::Unknown);
    }
}

/// Identity produced by calling a callee of the given identity.
fn call_result(callee: WebBinding) -> WebBinding {
    match callee {
        WebBinding::FlaskClass => WebBinding::FlaskApp,
        WebBinding::FlaskBlueprintClass => WebBinding::FlaskBlueprint,
        WebBinding::FlaskRequestClass => WebBinding::FlaskRequest,
        WebBinding::FlaskResponseClass
        | WebBinding::FlaskMakeResponse
        | WebBinding::FlaskJsonify => WebBinding::FlaskResponse,
        WebBinding::FastApiClass => WebBinding::FastApiApp,
        WebBinding::PathClass => WebBinding::PathInstance,
        WebBinding::FileLikeFactory => WebBinding::FileLikeObject,
        _ => WebBinding::Unknown,
    }
}

/// Module identity for `import x[.y][ as z]` (the bound name is the top
/// package unless aliased).
fn module_binding(module: &str) -> WebBinding {
    match module {
        "flask" | "flask.app" => WebBinding::FlaskModule,
        "flask.blueprints" => WebBinding::FlaskBlueprintsModule,
        "flask.globals" => WebBinding::FlaskGlobalsModule,
        "flask.helpers" => WebBinding::FlaskHelpersModule,
        "flask.json" => WebBinding::FlaskJsonModule,
        "flask.templating" => WebBinding::FlaskTemplatingModule,
        "flask.views" => WebBinding::FlaskViewsModule,
        "flask.wrappers" => WebBinding::FlaskWrappersModule,
        "fastapi" | "fastapi.applications" => WebBinding::FastApiModule,
        "fastapi.responses" | "starlette.responses" => WebBinding::FastApiResponsesModule,
        "starlette" => WebBinding::StarletteModule,
        "io" => WebBinding::IoModule,
        "tempfile" => WebBinding::TempfileModule,
        "codecs" => WebBinding::CodecsModule,
        "gzip" | "bz2" | "lzma" => WebBinding::CompressedIoModule,
        "os" => WebBinding::OsModule,
        "pathlib" => WebBinding::PathlibModule,
        _ => WebBinding::Unknown,
    }
}

/// Identity for `from <module> import <name>` bindings.
fn from_import_binding(module: Option<&str>, name: &str) -> WebBinding {
    match (module, name) {
        (Some("flask" | "flask.app"), "Flask") => WebBinding::FlaskClass,
        (Some("flask" | "flask.blueprints"), "Blueprint") => WebBinding::FlaskBlueprintClass,
        (Some("flask" | "flask.globals"), "request") => WebBinding::FlaskRequest,
        (Some("flask" | "flask.helpers"), "send_file") => WebBinding::FlaskSendFile,
        (Some("flask" | "flask.helpers"), "make_response") => WebBinding::FlaskMakeResponse,
        (Some("flask" | "flask.json"), "jsonify") => WebBinding::FlaskJsonify,
        (Some("flask" | "flask.templating"), "render_template") => WebBinding::FlaskRenderTemplate,
        (Some("flask" | "flask.templating"), "render_template_string") => {
            WebBinding::FlaskRenderTemplateString
        }
        (Some("flask" | "flask.views"), "View" | "MethodView") => WebBinding::FlaskViewClass,
        (Some("flask" | "flask.wrappers"), "Response") => WebBinding::FlaskResponseClass,
        (Some("flask" | "flask.wrappers"), "Request") => WebBinding::FlaskRequestClass,
        (Some("flask"), "app") => WebBinding::FlaskModule,
        (Some("flask"), "blueprints") => WebBinding::FlaskBlueprintsModule,
        (Some("flask"), "globals") => WebBinding::FlaskGlobalsModule,
        (Some("flask"), "helpers") => WebBinding::FlaskHelpersModule,
        (Some("flask"), "json") => WebBinding::FlaskJsonModule,
        (Some("flask"), "templating") => WebBinding::FlaskTemplatingModule,
        (Some("flask"), "views") => WebBinding::FlaskViewsModule,
        (Some("flask"), "wrappers") => WebBinding::FlaskWrappersModule,
        (Some("fastapi" | "fastapi.applications"), "FastAPI") => WebBinding::FastApiClass,
        (Some("fastapi" | "starlette"), "responses") => WebBinding::FastApiResponsesModule,
        (Some("fastapi" | "fastapi.responses" | "starlette.responses"), name)
            if name.ends_with("Response") =>
        {
            WebBinding::FastApiResponseClass
        }
        (
            Some("io"),
            "open" | "BytesIO" | "StringIO" | "BufferedReader" | "BufferedWriter"
            | "BufferedRandom" | "FileIO" | "TextIOWrapper",
        )
        | (
            Some("tempfile"),
            "TemporaryFile" | "NamedTemporaryFile" | "SpooledTemporaryFile" | "mkstemp",
        )
        | (Some("codecs" | "gzip" | "bz2" | "lzma" | "builtins"), "open")
        | (Some("os"), "fdopen") => WebBinding::FileLikeFactory,
        (Some("pathlib"), "Path") => WebBinding::PathClass,
        _ => WebBinding::Unknown,
    }
}

/// Identity of `base.attr` given the base's identity.
fn attribute_binding(base: WebBinding, attribute: &str) -> WebBinding {
    match (base, attribute) {
        (WebBinding::FlaskModule, "Flask") => WebBinding::FlaskClass,
        (WebBinding::FlaskModule | WebBinding::FlaskBlueprintsModule, "Blueprint") => {
            WebBinding::FlaskBlueprintClass
        }
        (WebBinding::FlaskModule | WebBinding::FlaskGlobalsModule, "request") => {
            WebBinding::FlaskRequest
        }
        (WebBinding::FlaskModule | WebBinding::FlaskHelpersModule, "send_file") => {
            WebBinding::FlaskSendFile
        }
        (WebBinding::FlaskModule | WebBinding::FlaskHelpersModule, "make_response") => {
            WebBinding::FlaskMakeResponse
        }
        (WebBinding::FlaskModule | WebBinding::FlaskJsonModule, "jsonify") => {
            WebBinding::FlaskJsonify
        }
        (WebBinding::FlaskModule | WebBinding::FlaskTemplatingModule, "render_template") => {
            WebBinding::FlaskRenderTemplate
        }
        (WebBinding::FlaskModule | WebBinding::FlaskTemplatingModule, "render_template_string") => {
            WebBinding::FlaskRenderTemplateString
        }
        (WebBinding::FlaskModule | WebBinding::FlaskViewsModule, "View" | "MethodView") => {
            WebBinding::FlaskViewClass
        }
        (WebBinding::FlaskModule | WebBinding::FlaskWrappersModule, "Response") => {
            WebBinding::FlaskResponseClass
        }
        (WebBinding::FlaskModule | WebBinding::FlaskWrappersModule, "Request") => {
            WebBinding::FlaskRequestClass
        }
        (WebBinding::FlaskModule, "app") => WebBinding::FlaskModule,
        (WebBinding::FlaskModule, "blueprints") => WebBinding::FlaskBlueprintsModule,
        (WebBinding::FlaskModule, "globals") => WebBinding::FlaskGlobalsModule,
        (WebBinding::FlaskModule, "helpers") => WebBinding::FlaskHelpersModule,
        (WebBinding::FlaskModule, "json") => WebBinding::FlaskJsonModule,
        (WebBinding::FlaskModule, "templating") => WebBinding::FlaskTemplatingModule,
        (WebBinding::FlaskModule, "views") => WebBinding::FlaskViewsModule,
        (WebBinding::FlaskModule, "wrappers") => WebBinding::FlaskWrappersModule,
        (WebBinding::FlaskApp | WebBinding::FlaskBlueprint, "errorhandler") => {
            WebBinding::FlaskErrorHandler
        }
        (WebBinding::FlaskBlueprint, "app_errorhandler") => WebBinding::FlaskErrorHandler,
        (WebBinding::FlaskApp | WebBinding::FlaskBlueprint, "route") => WebBinding::FlaskRoute,
        (WebBinding::FlaskApp, "preprocess_request") => WebBinding::FlaskPreprocessRequest,
        (WebBinding::FlaskRequest | WebBinding::FlaskResponse, "headers") => {
            WebBinding::WerkzeugHeaders
        }
        (WebBinding::FastApiModule, "FastAPI") => WebBinding::FastApiClass,
        (WebBinding::FastApiModule | WebBinding::StarletteModule, "responses") => {
            WebBinding::FastApiResponsesModule
        }
        (WebBinding::FastApiModule | WebBinding::FastApiResponsesModule, attribute)
            if attribute.ends_with("Response") =>
        {
            WebBinding::FastApiResponseClass
        }
        (
            WebBinding::FastApiApp,
            "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "trace",
        ) => WebBinding::FastApiRouteMethod,
        (
            WebBinding::IoModule,
            "open" | "BytesIO" | "StringIO" | "BufferedReader" | "BufferedWriter"
            | "BufferedRandom" | "FileIO" | "TextIOWrapper",
        )
        | (
            WebBinding::TempfileModule,
            "TemporaryFile" | "NamedTemporaryFile" | "SpooledTemporaryFile" | "mkstemp",
        )
        | (
            WebBinding::CodecsModule | WebBinding::CompressedIoModule | WebBinding::PathInstance,
            "open",
        )
        | (WebBinding::OsModule, "fdopen") => WebBinding::FileLikeFactory,
        (WebBinding::PathlibModule, "Path") => WebBinding::PathClass,
        _ => WebBinding::Unknown,
    }
}

/// Builtin fallback for unbound names.
fn fallback_binding(name: &str) -> WebBinding {
    match name {
        "open" => WebBinding::FileLikeFactory,
        _ => WebBinding::Unknown,
    }
}
