use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, for_each_expr, for_each_stmt_in_scope, issue_at, keyword_range, keyword_value,
    stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Arguments, Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::{HashMap, HashSet};
use std::path::Path;

// --- python:S4507 — debug features left enabled --------------------------------
//
// Mirrors Sonar's `DebugModeCheck`: only specific framework debug entry points
// are findings — `django.conf.settings.configure(DEBUG=...)`,
// `flask.app.Flask.run(debug=...)` / `app.debug = ...` /
// `app.config["DEBUG"] = ...`, `flask_graphql.GraphQLView.as_view(graphiql=...)`
// (including local subclasses), and `DEBUG`/`DEBUG_PROPAGATE_EXCEPTIONS`
// assignments inside `settings.py`/`global_settings.py`. A generic
// `debug=True` keyword on an arbitrary call and debugger hooks such as
// `breakpoint()`/`pdb.set_trace()` are not findings.

const SONAR_MESSAGE: &str =
    "Make sure this debug feature is deactivated before delivering the code in production.";
const DEBUG_PROPERTIES: [&str; 2] = ["DEBUG", "DEBUG_PROPAGATE_EXCEPTIONS"];
const SETTING_FILES: [&str; 2] = ["global_settings.py", "settings.py"];

pub(crate) fn check_debug_features(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    path: &Path,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let settings_file = path
        .file_name()
        .is_some_and(|name| SETTING_FILES.contains(&name.to_string_lossy().as_ref()));
    let mut module_bindings = ScopeBindings::default();
    visit_scope(
        file_ctx.module_body,
        &mut module_bindings,
        settings_file,
        index,
        source,
        &mut issues,
    );
    issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    Unknown,
    Django,
    DjangoConf,
    DjangoSettings,
    DjangoConfigure,
    FlaskModule,
    FlaskAppModule,
    FlaskClass,
    FlaskApp,
    FlaskRun,
    FlaskDebug,
    FlaskConfig,
    GraphqlModule,
    GraphqlView,
    GraphqlAsView,
    GraphqlServerModule,
    GraphqlServerFlaskModule,
}

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, Binding>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    settings_file: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        visit_statement_expressions(statement, bindings, index, source, issues);
        visit_statement_assignments(statement, bindings, settings_file, index, source, issues);
        visit_nested_scopes(statement, bindings, settings_file, index, source, issues);
        bind_statement(statement, bindings);
    }
}
fn visit_statement_expressions(
    statement: &Stmt,
    bindings: &ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for expression in stmt_exprs(statement) {
        for_each_expr(expression, &mut |expression| {
            let Expr::Call(call) = expression else {
                return;
            };
            // Sonar only inspects qualified callees (`x.y(...)`) with at
            // least one argument; bare names and empty calls never match.
            if !matches!(call.func.as_ref(), Expr::Attribute(_))
                || (call.arguments.args.is_empty() && call.arguments.keywords.is_empty())
            {
                return;
            }
            match identity_of_expr(&call.func, bindings) {
                Binding::DjangoConfigure => {
                    for setting in DEBUG_PROPERTIES {
                        if keyword_value(&call.arguments, setting).is_some_and(is_debug_value)
                            && let Some(range) = keyword_range(&call.arguments, setting)
                        {
                            issues.push(issue_at(
                                "python:S4507",
                                SONAR_MESSAGE,
                                range,
                                index,
                                source,
                            ));
                        }
                    }
                }
                Binding::FlaskRun => {
                    // `flask.app.Flask.run`: the `debug` keyword or the third
                    // positional argument (Sonar `nthArgumentOrKeyword(2, …)`).
                    if let Some((range, value)) =
                        nth_argument_or_keyword(&call.arguments, 2, "debug")
                        && is_debug_value(value)
                    {
                        issues.push(issue_at(
                            "python:S4507",
                            SONAR_MESSAGE,
                            range,
                            index,
                            source,
                        ));
                    }
                }
                Binding::GraphqlAsView => {
                    // `flask_graphql.GraphQLView.as_view`: keyword-only
                    // `graphiql` (Sonar `nthArgumentOrKeyword(-1, …)`).
                    if let Some((range, value)) =
                        nth_argument_or_keyword(&call.arguments, usize::MAX, "graphiql")
                        && is_debug_value(value)
                    {
                        issues.push(issue_at(
                            "python:S4507",
                            SONAR_MESSAGE,
                            range,
                            index,
                            source,
                        ));
                    }
                }
                _ => {}
            }
        });
    }
}

/// Sonar `TreeUtils.nthArgumentOrKeyword`: the keyword argument named `name`,
/// or the positional argument at `index` when it precedes every keyword.
/// `usize::MAX` disables the positional arm (Sonar's `-1`).
fn nth_argument_or_keyword<'a>(
    arguments: &'a Arguments,
    index: usize,
    name: &str,
) -> Option<(TextRange, &'a Expr)> {
    if let Some(value) = arguments.args.get(index)
        && !matches!(value, Expr::Starred(_))
    {
        return Some((value.range(), value));
    }
    arguments.keywords.iter().find_map(|keyword| {
        let arg = keyword.arg.as_ref()?;
        (arg.as_str() == name).then_some((keyword.range(), &keyword.value))
    })
}

fn visit_statement_assignments(
    statement: &Stmt,
    bindings: &ScopeBindings,
    settings_file: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let (targets, value) = match statement {
        Stmt::Assign(assign) => (assign.targets.as_slice(), Some(assign.value.as_ref())),
        Stmt::AnnAssign(assign) => (
            std::slice::from_ref(assign.target.as_ref()),
            assign.value.as_deref(),
        ),
        _ => return,
    };
    let Some(value) = value else {
        return;
    };
    if targets
        .iter()
        .any(|target| target_is_debug_property(target, bindings, settings_file))
        && is_debug_value(value)
    {
        issues.push(issue_at(
            "python:S4507",
            SONAR_MESSAGE,
            statement.range(),
            index,
            source,
        ));
    }
}

fn target_is_debug_property(target: &Expr, bindings: &ScopeBindings, settings_file: bool) -> bool {
    match target {
        Expr::Name(name) => settings_file && DEBUG_PROPERTIES.contains(&name.id.as_str()),
        Expr::Attribute(_) => identity_of_expr(target, bindings) == Binding::FlaskDebug,
        Expr::Subscript(subscript) => {
            identity_of_expr(&subscript.value, bindings) == Binding::FlaskConfig
                && matches!(
                    subscript.slice.as_ref(),
                    Expr::StringLiteral(literal)
                        if literal.value.iter().any(|part| part.value.as_ref() == "DEBUG")
                )
        }
        _ => false,
    }
}

/// Sonar `DebugModeCheck.isTrue`: a truthy literal, or a name bound to one of
/// the debug property identifiers (`DEBUG`, `DEBUG_PROPAGATE_EXCEPTIONS`).
fn is_debug_value(expr: &Expr) -> bool {
    is_truthy_literal(expr)
        || matches!(expr, Expr::Name(name) if DEBUG_PROPERTIES.contains(&name.id.as_str()))
}

/// Literal-level truthiness matching Sonar's `Expressions.isTruthy`: `True`,
/// non-zero numbers, non-empty strings/bytes/f-strings, non-empty collections,
/// `Ellipsis`, and unary `+`/`-` applied to a truthy literal.
fn is_truthy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::BooleanLiteral(literal) => literal.value,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() != Some(0),
            ruff_python_ast::Number::Float(value) => *value != 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real != 0.0 || *imag != 0.0,
        },
        Expr::StringLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::BytesLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::FString(_) | Expr::EllipsisLiteral(_) => true,
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        Expr::UnaryOp(unary) => {
            matches!(
                unary.op,
                ruff_python_ast::UnaryOp::UAdd | ruff_python_ast::UnaryOp::USub
            ) && is_truthy_literal(&unary.operand)
        }
        _ => false,
    }
}

fn visit_nested_scopes(
    statement: &Stmt,
    bindings: &mut ScopeBindings,
    settings_file: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    match statement {
        Stmt::FunctionDef(function) => {
            let mut child = child_scope(bindings, &function.body, Some(function));
            visit_scope(
                &function.body,
                &mut child,
                settings_file,
                index,
                source,
                issues,
            );
        }
        Stmt::ClassDef(class) => {
            let mut child = child_scope(bindings, &class.body, None);
            visit_scope(
                &class.body,
                &mut child,
                settings_file,
                index,
                source,
                issues,
            );
        }
        _ => {
            for body in child_bodies(statement) {
                visit_scope(body, bindings, settings_file, index, source, issues);
            }
        }
    }
}

fn child_scope(
    parent: &ScopeBindings,
    suite: &[Stmt],
    function: Option<&StmtFunctionDef>,
) -> ScopeBindings {
    let mut child = parent.clone();
    let mut locals = HashSet::new();
    for_each_stmt_in_scope(suite, &mut |statement| {
        locals.extend(stmt_store_names(statement));
    });
    if let Some(function) = function {
        for parameter in function
            .parameters
            .posonlyargs
            .iter()
            .chain(&function.parameters.args)
            .chain(&function.parameters.kwonlyargs)
        {
            locals.insert(parameter.parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.vararg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
        if let Some(parameter) = function.parameters.kwarg.as_deref() {
            locals.insert(parameter.name.as_str().to_string());
        }
    }
    for local in locals {
        child.values.insert(local, Binding::Unknown);
    }
    // Parameter annotations carry framework identity (`def serve(app: Flask)`).
    if let Some(function) = function {
        for parameter in function
            .parameters
            .posonlyargs
            .iter()
            .chain(&function.parameters.args)
            .chain(&function.parameters.kwonlyargs)
        {
            if let Some(annotation) = parameter.parameter.annotation.as_deref() {
                let binding = identity_of_expr(annotation, parent);
                if binding != Binding::Unknown {
                    child
                        .values
                        .insert(parameter.parameter.name.as_str().to_string(), binding);
                }
            }
        }
    }
    child
}

fn bind_statement(statement: &Stmt, bindings: &mut ScopeBindings) {
    match statement {
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
                let binding = match (alias.name.as_str(), alias.asname.is_some()) {
                    ("django", _) | ("django.conf", false) => Binding::Django,
                    ("django.conf", true) => Binding::DjangoConf,
                    ("django.conf.settings", _) => Binding::DjangoSettings,
                    ("flask", _) | ("flask.app", false) => Binding::FlaskModule,
                    ("flask.app", true) => Binding::FlaskAppModule,
                    ("flask_graphql", _) => Binding::GraphqlModule,
                    ("graphql_server", _) | ("graphql_server.flask", false) => {
                        Binding::GraphqlServerModule
                    }
                    ("graphql_server.flask", true) => Binding::GraphqlServerFlaskModule,
                    _ => Binding::Unknown,
                };
                bindings.values.insert(local, binding);
            }
        }
        Stmt::ImportFrom(import) => {
            let module = import
                .module
                .as_ref()
                .map(ruff_python_ast::Identifier::as_str);
            for alias in &import.names {
                let local = alias
                    .asname
                    .as_deref()
                    .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
                let binding = match (module, alias.name.as_str()) {
                    (Some("django"), "conf") => Binding::DjangoConf,
                    (Some("django.conf"), "settings") => Binding::DjangoSettings,
                    (Some("flask"), "app") => Binding::FlaskAppModule,
                    (Some("flask" | "flask.app"), "Flask") => Binding::FlaskClass,
                    (Some("flask_graphql" | "graphql_server.flask"), "GraphQLView") => {
                        Binding::GraphqlView
                    }
                    _ => Binding::Unknown,
                };
                bindings.values.insert(local, binding);
            }
        }
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                bind_name_target(target, &assign.value, bindings);
            }
        }
        Stmt::AnnAssign(assign) => {
            let annotated = identity_of_expr(&assign.annotation, bindings);
            let binding = if annotated == Binding::Unknown {
                assign
                    .value
                    .as_deref()
                    .map_or(Binding::Unknown, |value| instance_binding(value, bindings))
            } else {
                annotated
            };
            bind_target_as(&assign.target, binding, bindings);
        }
        Stmt::ClassDef(class) => {
            let binding = class
                .bases()
                .iter()
                .map(|base| identity_of_expr(base, bindings))
                .find(|binding| *binding != Binding::Unknown)
                .unwrap_or(Binding::Unknown);
            bindings
                .values
                .insert(class.name.as_str().to_string(), binding);
        }
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, Binding::Unknown);
            }
        }
    }
}

/// Binds a plain-assignment target to the value's framework identity. Sequence
/// unpacking binds element-wise when the shapes line up; anything else falls
/// back to `Unknown`, matching the previous behavior for non-name targets.
fn bind_name_target(target: &Expr, value: &Expr, bindings: &mut ScopeBindings) {
    match target {
        Expr::Name(name) => {
            let binding = instance_binding(value, bindings);
            bindings
                .values
                .insert(name.id.as_str().to_string(), binding);
        }
        Expr::Tuple(tuple) => bind_sequence_target(&tuple.elts, value, bindings),
        Expr::List(list) => bind_sequence_target(&list.elts, value, bindings),
        _ => {
            let mut names = Vec::new();
            crate::support::collect_target_names(target, &mut names);
            for name in names {
                bindings.values.insert(name, Binding::Unknown);
            }
        }
    }
}

fn bind_sequence_target(elts: &[Expr], value: &Expr, bindings: &mut ScopeBindings) {
    let values: Option<&[Expr]> = match value {
        Expr::Tuple(tuple) => Some(&tuple.elts),
        Expr::List(list) => Some(&list.elts),
        _ => None,
    };
    if let Some(values) = values
        && values.len() == elts.len()
    {
        for (target, element) in elts.iter().zip(values) {
            bind_name_target(target, element, bindings);
        }
        return;
    }
    let mut names = Vec::new();
    for target in elts {
        crate::support::collect_target_names(target, &mut names);
    }
    for name in names {
        bindings.values.insert(name, Binding::Unknown);
    }
}

/// Binds a single-target write (`x = …`, `x: T = …`) to `binding`; non-name
/// targets keep the previous `Unknown` behavior.
fn bind_target_as(target: &Expr, binding: Binding, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings
            .values
            .insert(name.id.as_str().to_string(), binding);
        return;
    }
    let mut names = Vec::new();
    crate::support::collect_target_names(target, &mut names);
    for name in names {
        bindings.values.insert(name, Binding::Unknown);
    }
}

/// Framework identity carried by a constructed value: `Flask(...)` yields a
/// Flask application, `GraphQLView(...)` a GraphQL view; everything else is
/// `Unknown`.
fn instance_binding(expr: &Expr, bindings: &ScopeBindings) -> Binding {
    match expr {
        Expr::Call(call) => match identity_of_expr(&call.func, bindings) {
            Binding::FlaskClass => Binding::FlaskApp,
            Binding::GraphqlView => Binding::GraphqlView,
            _ => Binding::Unknown,
        },
        // `alias = app` / `alias = flask.app` propagate the bound identity.
        Expr::Name(_) | Expr::Attribute(_) => identity_of_expr(expr, bindings),
        _ => Binding::Unknown,
    }
}

fn identity_of_expr(expr: &Expr, bindings: &ScopeBindings) -> Binding {
    match expr {
        Expr::Name(name) => bindings
            .values
            .get(name.id.as_str())
            .copied()
            .unwrap_or(Binding::Unknown),
        Expr::Attribute(attribute) => {
            let parent = identity_of_expr(attribute.value.as_ref(), bindings);
            match (parent, attribute.attr.as_str()) {
                (Binding::Django, "conf") => Binding::DjangoConf,
                (Binding::DjangoConf, "settings") => Binding::DjangoSettings,
                (Binding::DjangoSettings, "configure") => Binding::DjangoConfigure,
                (Binding::FlaskModule, "app") => Binding::FlaskAppModule,
                (Binding::FlaskModule | Binding::FlaskAppModule, "Flask") => Binding::FlaskClass,
                (Binding::FlaskApp, "run") => Binding::FlaskRun,
                (Binding::FlaskApp, "debug") => Binding::FlaskDebug,
                (Binding::FlaskApp, "config") => Binding::FlaskConfig,
                (Binding::GraphqlModule | Binding::GraphqlServerFlaskModule, "GraphQLView") => {
                    Binding::GraphqlView
                }
                (Binding::GraphqlView, "as_view") => Binding::GraphqlAsView,
                (Binding::GraphqlServerModule, "flask") => Binding::GraphqlServerFlaskModule,
                _ => Binding::Unknown,
            }
        }
        _ => Binding::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan, scan_at};
    use std::path::PathBuf;

    #[test]
    fn s4507_flags_django_debug_configuration() {
        let source = concat!(
            "from django.conf import settings\n",
            "\n",
            "settings.configure(DEBUG=True)\n",
            "settings.configure(DEBUG_PROPAGATE_EXCEPTIONS=True)\n",
            "DEBUG = True\n",
            "DEBUG_PROPAGATE_EXCEPTIONS = True\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S4507");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|issue| issue.message
            == "Make sure this debug feature is deactivated before delivering the code in production."));
        assert_eq!(
            found
                .iter()
                .map(|issue| (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.range.end.line,
                    issue.range.end.column
                ))
                .collect::<Vec<_>>(),
            vec![(3, 19, 3, 29), (4, 19, 4, 50)]
        );
    }

    #[test]
    fn s4507_preserves_disabled_and_runtime_django_debug_configuration() {
        let safe = concat!(
            "from django.conf import settings\n",
            "\n",
            "settings.configure(DEBUG=False)\n",
            "settings.configure(DEBUG_PROPAGATE_EXCEPTIONS=False)\n"
        );
        assert!(findings(&scan(safe), "python:S4507").is_empty());
        let near_miss = concat!(
            "from django.conf import settings\n",
            "\n",
            "def configure_for_environment(debug_mode):\n",
            "    settings.configure(DEBUG=debug_mode)\n"
        );
        assert!(findings(&scan(near_miss), "python:S4507").is_empty());
    }

    #[test]
    fn s4507_ignores_debug_hooks_and_unresolved_debug_kwargs() {
        // Sonar's DebugModeCheck does not cover debugger hooks, and a
        // `debug=True` kwarg on an unresolved receiver is not a finding.
        let report = scan("breakpoint()\npdb.set_trace()\napp.run(debug=True)\n");
        assert!(findings(&report, "python:S4507").is_empty());
    }

    #[test]
    fn s4507_ignores_generic_debug_kwargs() {
        // Issue #641: `debug=True` on an arbitrary callable is not a Sonar
        // finding — only the documented framework entry points are.
        let source = concat!(
            "from django.template import Engine\n",
            "DEBUG_ENGINE = Engine(debug=True)\n",
            "run(app, debug=True)\n",
            "helper(name=\"x\", debug=True)\n"
        );
        assert!(findings(&scan(source), "python:S4507").is_empty());
    }

    #[test]
    fn s4507_flags_flask_app_debug_entry_points() {
        let source = concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "app.run(debug=True)\n",
            "app.debug = True\n",
            "app.config[\"DEBUG\"] = True\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S4507");
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|issue| issue.message
            == "Make sure this debug feature is deactivated before delivering the code in production."));
    }

    #[test]
    fn s4507_flags_flask_module_qualified_and_positional_debug() {
        let source = concat!(
            "import flask\n",
            "app = flask.Flask(__name__)\n",
            "app.run(\"0.0.0.0\", 8080, True)\n"
        );
        assert_eq!(findings(&scan(source), "python:S4507").len(), 1);
    }

    #[test]
    fn s4507_ignores_flask_debug_disabled_and_non_flask_receivers() {
        let source = concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "app.run(debug=False)\n",
            "app.debug = False\n",
            "app.config[\"DEBUG\"] = False\n",
            "other = make_runner()\n",
            "other.run(debug=True)\n",
            "other.debug = True\n"
        );
        assert!(findings(&scan(source), "python:S4507").is_empty());
    }

    #[test]
    fn s4507_flags_graphql_view_graphiql() {
        let source = concat!(
            "from flask_graphql import GraphQLView\n",
            "view = GraphQLView.as_view(\"graphql\", schema=schema, graphiql=True)\n"
        );
        let report = scan(source);
        let found = findings(&report, "python:S4507");
        assert_eq!(found.len(), 1);
        let subclassed = concat!(
            "from graphql_server.flask import GraphQLView\n",
            "class MyView(GraphQLView):\n",
            "    pass\n",
            "view = MyView.as_view(\"graphql\", graphiql=True)\n"
        );
        assert_eq!(findings(&scan(subclassed), "python:S4507").len(), 1);
        let disabled = concat!(
            "from flask_graphql import GraphQLView\n",
            "view = GraphQLView.as_view(\"graphql\", schema=schema)\n",
            "other = GraphQLView.as_view(\"graphql\", graphiql=False)\n"
        );
        assert!(findings(&scan(disabled), "python:S4507").is_empty());
    }

    #[test]
    fn s4507_flags_debug_names_in_django_settings_files() {
        let source = "DEBUG = True\nDEBUG_PROPAGATE_EXCEPTIONS = True\nOTHER = True\n";
        let flagged = scan_at(PathBuf::from("settings.py"), source);
        let found = findings(&flagged, "python:S4507");
        assert_eq!(found.len(), 2);
        let global = scan_at(PathBuf::from("global_settings.py"), "DEBUG = True\n");
        assert_eq!(findings(&global, "python:S4507").len(), 1);
        // Outside a Django settings file the same names are not findings.
        let plain = scan_at(PathBuf::from("config.py"), source);
        assert!(findings(&plain, "python:S4507").is_empty());
        let disabled = scan_at(PathBuf::from("settings.py"), "DEBUG = False\n");
        assert!(findings(&disabled, "python:S4507").is_empty());
    }

    #[test]
    fn s4507_tracks_django_settings_aliases_and_rebinding() {
        let aliased = concat!(
            "import django.conf as conf\n",
            "\n",
            "conf.settings.configure(DEBUG=True)\n"
        );
        assert_eq!(findings(&scan(aliased), "python:S4507").len(), 1);
        let rebound = concat!(
            "from django.conf import settings\n",
            "settings = object()\n",
            "\n",
            "settings.configure(DEBUG=True)\n"
        );
        assert!(findings(&scan(rebound), "python:S4507").is_empty());
    }
}
