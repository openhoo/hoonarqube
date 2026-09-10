use crate::engine::file_context::FileContext;
use crate::support::{
    child_bodies, dotted_name, for_each_expr, for_each_stmt_in_scope, is_true_literal, issue_at,
    keyword_range, keyword_value, stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::{HashMap, HashSet};

// --- python:S4507 — debug features left enabled --------------------------------

pub(crate) fn check_debug_features(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut module_bindings = ScopeBindings::default();
    visit_scope(
        file_ctx.module_body,
        &mut module_bindings,
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
}
const DEBUG_CALLS: [&str; 4] = [
    "breakpoint",
    "pdb.set_trace",
    "ipdb.set_trace",
    "celery.contrib.rdb.set_trace",
];

#[derive(Clone, Default)]
struct ScopeBindings {
    values: HashMap<String, Binding>,
}

fn visit_scope(
    suite: &[Stmt],
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for statement in suite {
        visit_statement_expressions(statement, bindings, index, source, issues);
        visit_nested_scopes(statement, bindings, index, source, issues);
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
            let debug_call =
                dotted_name(&call.func).is_some_and(|path| DEBUG_CALLS.contains(&path.as_str()));
            if debug_call || keyword_value(&call.arguments, "debug").is_some_and(is_true_literal) {
                issues.push(issue_at(
                    "python:S4507",
                    "Remove this debug feature before shipping to production.",
                    call.range(),
                    index,
                    source,
                ));
            }
            if identity_of_expr(&call.func, bindings) != Binding::DjangoConfigure {
                return;
            }
            for setting in ["DEBUG", "DEBUG_PROPAGATE_EXCEPTIONS"] {
                if keyword_value(&call.arguments, setting).is_some_and(is_true_literal)
                    && let Some(range) = keyword_range(&call.arguments, setting)
                {
                    issues.push(issue_at(
                        "python:S4507",
                        "Make sure this debug feature is deactivated before delivering the code in production.",
                        range,
                        index,
                        source,
                    ));
                }
            }
        });
    }
}

fn visit_nested_scopes(
    statement: &Stmt,
    bindings: &mut ScopeBindings,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    match statement {
        Stmt::FunctionDef(function) => {
            let mut child = child_scope(bindings, &function.body, Some(function));
            visit_scope(&function.body, &mut child, index, source, issues);
        }
        Stmt::ClassDef(class) => {
            let mut child = child_scope(bindings, &class.body, None);
            visit_scope(&class.body, &mut child, index, source, issues);
        }
        _ => {
            for body in child_bodies(statement) {
                visit_scope(body, bindings, index, source, issues);
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
                    _ => Binding::Unknown,
                };
                bindings.values.insert(local, binding);
            }
        }
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                bind_target(target, bindings);
            }
        }
        Stmt::AnnAssign(assign) => bind_target(&assign.target, bindings),
        _ => {
            for name in stmt_store_names(statement) {
                bindings.values.insert(name, Binding::Unknown);
            }
        }
    }
}

fn bind_target(target: &Expr, bindings: &mut ScopeBindings) {
    if let Expr::Name(name) = target {
        bindings
            .values
            .insert(name.id.as_str().to_string(), Binding::Unknown);
        return;
    }
    let mut names = Vec::new();
    crate::support::collect_target_names(target, &mut names);
    for name in names {
        bindings.values.insert(name, Binding::Unknown);
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
                _ => Binding::Unknown,
            }
        }
        _ => Binding::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

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
    fn s4507_retains_debug_hooks_and_flags_lowercase_debug() {
        let report = scan("breakpoint()\napp.run(debug=True)\n");
        let found = findings(&report, "python:S4507");
        assert_eq!(found.len(), 2);
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
