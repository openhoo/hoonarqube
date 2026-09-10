use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::issue_at;
use crate::support::stmt_store_names;
use crate::support::{decorator_callee_path, dotted_name};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

pub(crate) fn check_route_decorator_ordering(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        if function.decorator_list.len() < 2 {
            continue;
        }

        for (position, decorator) in function.decorator_list.iter().enumerate() {
            let Some(decorator_name) =
                recognized_web_entry_decorator(&decorator.expression, function, file_ctx)
            else {
                continue;
            };
            if position == 0 {
                continue;
            }
            let message = format!(
                "Move this '{decorator_name}' decorator to the top of the other decorators."
            );
            issues.push(issue_at(
                "python:S6552",
                &message,
                decorator.expression.range(),
                index,
                source,
            ));
            break;
        }
    }
    issues
}

fn recognized_web_entry_decorator(
    expression: &Expr,
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> Option<&'static str> {
    let path = decorator_callee_path(expression)?;
    let before = expression.range().start();
    if path.rsplit('.').next() == Some("receiver")
        && django_receiver_is_bound(&path, before, function, file_ctx)
    {
        return Some("@receiver");
    }
    if path.rsplit('.').next() == Some("route")
        && flask_route_is_bound(&path, before, function, file_ctx)
    {
        return Some("@route");
    }
    None
}

fn django_receiver_is_bound(
    path: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    match parts.as_slice() {
        [local] => imported_from_is_current(
            file_ctx,
            local,
            "django.dispatch",
            "receiver",
            before,
            function,
        ),
        [module, receiver] if *receiver == "receiver" => {
            plain_module_is_current(file_ctx, module, "django.dispatch", before, function)
                || (plain_module_is_current(file_ctx, module, "django", before, function)
                    && *module == "django")
        }
        [root, dispatch, receiver] if *dispatch == "dispatch" && *receiver == "receiver" => {
            plain_module_is_current(file_ctx, root, "django", before, function)
        }
        _ => false,
    }
}

fn flask_route_is_bound(
    path: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() == 2 && parts[1] == "route" {
        let local = parts[0];
        imported_from_is_current(file_ctx, local, "flask", "Flask", before, function)
            || imported_from_is_current(file_ctx, local, "flask.app", "Flask", before, function)
            || imported_from_is_current(file_ctx, local, "flask", "Blueprint", before, function)
            || imported_from_is_current(
                file_ctx,
                local,
                "flask.blueprints",
                "Blueprint",
                before,
                function,
            )
            || flask_instance_is_current(local, before, function, file_ctx)
    } else if parts.len() == 3 && parts[2] == "route" {
        let module = parts[0];
        let class = parts[1];
        (class == "Flask" || class == "Blueprint")
            && plain_module_is_current(file_ctx, module, "flask", before, function)
    } else {
        false
    }
}

fn flask_instance_is_current(
    local: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    let target_scope = decorator_scope(function, file_ctx);
    let Some(binding) = file_ctx
        .stmts
        .iter()
        .filter_map(|statement| {
            let (target, value) = match *statement {
                Stmt::Assign(assign) if assign.targets.len() == 1 => {
                    (assign.targets.first()?, assign.value.as_ref())
                }
                Stmt::AnnAssign(assign) => (assign.target.as_ref(), assign.value.as_deref()?),
                _ => return None,
            };
            if !matches!(target, Expr::Name(name) if name.id.as_str() == local)
                || statement.range().end() > before
                || !scope_is_visible(
                    scope_identity_for_range(file_ctx, statement.range()),
                    target_scope,
                )
            {
                return None;
            }
            let Expr::Call(call) = value else {
                return None;
            };
            let path = dotted_name(&call.func)?;
            flask_constructor_is_bound(&path, call.range().start(), function, file_ctx)
                .then_some(statement.range())
        })
        .max_by_key(Ranged::start)
    else {
        return false;
    };
    !binding_is_shadowed(file_ctx, local, binding, before, function)
}

fn flask_constructor_is_bound(
    path: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    match parts.as_slice() {
        [local] => {
            imported_from_is_current(file_ctx, local, "flask", "Flask", before, function)
                || imported_from_is_current(file_ctx, local, "flask.app", "Flask", before, function)
                || imported_from_is_current(file_ctx, local, "flask", "Blueprint", before, function)
                || imported_from_is_current(
                    file_ctx,
                    local,
                    "flask.blueprints",
                    "Blueprint",
                    before,
                    function,
                )
        }
        [module, class] if *class == "Flask" || *class == "Blueprint" => {
            plain_module_is_current(file_ctx, module, "flask", before, function)
        }
        _ => false,
    }
}

fn imported_from_is_current(
    file_ctx: &FileContext<'_>,
    local: &str,
    module: &str,
    imported: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
) -> bool {
    let target_scope = decorator_scope(function, file_ctx);
    let Some(binding) = file_ctx
        .imports
        .iter()
        .filter_map(|entry| {
            let AnyImport::From(import) = entry else {
                return None;
            };
            if import.level != 0
                || import
                    .module
                    .as_ref()
                    .map(ruff_python_ast::Identifier::as_str)
                    != Some(module)
            {
                return None;
            }
            import.names.iter().find_map(|alias| {
                let alias_local = alias
                    .asname
                    .as_ref()
                    .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str);
                let binding = alias.range();
                (alias.name.as_str() == imported
                    && alias_local == local
                    && binding.end() <= before
                    && scope_is_visible(scope_identity_for_range(file_ctx, binding), target_scope))
                .then_some(binding)
            })
        })
        .max_by_key(Ranged::start)
    else {
        return false;
    };
    !binding_is_shadowed(file_ctx, local, binding, before, function)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ScopeIdentity {
    kind: ScopeKind,
    range: Option<TextRange>,
}

fn scope_identity_for_range(file_ctx: &FileContext<'_>, target: TextRange) -> ScopeIdentity {
    let mut best = ScopeIdentity {
        kind: ScopeKind::Module,
        range: None,
    };
    let mut best_len = u32::MAX;
    for function in &file_ctx.functions {
        let range = function.range();
        let length = range.end().to_u32() - range.start().to_u32();
        if range.contains_range(target) && length < best_len {
            best = ScopeIdentity {
                kind: ScopeKind::Function,
                range: Some(range),
            };
            best_len = length;
        }
    }
    for class in &file_ctx.classes {
        let range = class.range();
        let length = range.end().to_u32() - range.start().to_u32();
        if range.contains_range(target) && length < best_len {
            best = ScopeIdentity {
                kind: ScopeKind::Class,
                range: Some(range),
            };
            best_len = length;
        }
    }
    best
}

fn decorator_scope(
    function: &ruff_python_ast::StmtFunctionDef,
    file_ctx: &FileContext<'_>,
) -> ScopeIdentity {
    let function_range = function.range();
    let mut best = ScopeIdentity {
        kind: ScopeKind::Module,
        range: None,
    };
    let mut best_len = u32::MAX;
    for candidate in &file_ctx.functions {
        let range = candidate.range();
        if range == function_range {
            continue;
        }
        let length = range.end().to_u32() - range.start().to_u32();
        if range.contains_range(function_range) && length < best_len {
            best = ScopeIdentity {
                kind: ScopeKind::Function,
                range: Some(range),
            };
            best_len = length;
        }
    }
    for candidate in &file_ctx.classes {
        let range = candidate.range();
        let length = range.end().to_u32() - range.start().to_u32();
        if range.contains_range(function_range) && length < best_len {
            best = ScopeIdentity {
                kind: ScopeKind::Class,
                range: Some(range),
            };
            best_len = length;
        }
    }
    best
}

fn scope_is_visible(candidate: ScopeIdentity, target: ScopeIdentity) -> bool {
    match candidate.kind {
        ScopeKind::Module => true,
        ScopeKind::Function | ScopeKind::Class => target
            .range
            .is_some_and(|target_range| candidate.range.unwrap().contains_range(target_range)),
    }
}

fn plain_module_is_current(
    file_ctx: &FileContext<'_>,
    local: &str,
    module: &str,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
) -> bool {
    let target_scope = decorator_scope(function, file_ctx);
    let Some(binding) = file_ctx
        .imports
        .iter()
        .filter_map(|entry| {
            let AnyImport::Plain(import) = entry else {
                return None;
            };
            import.names.iter().find_map(|alias| {
                let alias_local = alias.asname.as_ref().map_or_else(
                    || alias.name.as_str().split('.').next().unwrap_or(""),
                    ruff_python_ast::Identifier::as_str,
                );
                let binding = alias.range();
                (alias.name.as_str() == module
                    && alias_local == local
                    && binding.end() <= before
                    && scope_is_visible(scope_identity_for_range(file_ctx, binding), target_scope))
                .then_some(binding)
            })
        })
        .max_by_key(Ranged::start)
    else {
        return false;
    };
    !binding_is_shadowed(file_ctx, local, binding, before, function)
}

fn binding_is_shadowed(
    file_ctx: &FileContext<'_>,
    local: &str,
    binding: TextRange,
    before: TextSize,
    function: &ruff_python_ast::StmtFunctionDef,
) -> bool {
    let target_scope = decorator_scope(function, file_ctx);
    if target_scope.kind == ScopeKind::Function
        && target_scope.range.is_some_and(|target_range| {
            file_ctx.functions.iter().any(|candidate| {
                candidate.range() == target_range
                    && candidate
                        .parameters
                        .iter()
                        .any(|parameter| parameter.name().as_str() == local)
            })
        })
    {
        return true;
    }

    let binding_scope = scope_identity_for_range(file_ctx, binding);
    file_ctx.stmts.iter().any(|statement| {
        let start = statement.range().start();
        let scope = scope_identity_for_range(file_ctx, statement.range());
        (scope == binding_scope || scope == target_scope)
            && start >= binding.end()
            && start < before
            && stmt_store_names(statement).iter().any(|name| name == local)
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6552_requires_bound_web_entry_decorator_outermost() {
        let flagged = scan(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "@login_required\n",
            "@app.route('/x')\n",
            "def handler():\n",
            "    return 1\n",
            "@app.route('/y')\n",
            "def good():\n",
            "    return 2\n"
        ));
        assert_eq!(findings(&flagged, "python:S6552").len(), 1);

        let method = scan(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "@login_required\n",
            "@app.get('/x')\n",
            "def handler():\n",
            "    return 1\n"
        ));
        assert!(findings(&method, "python:S6552").is_empty());
    }

    #[test]
    fn s6552_rejects_unrelated_or_shadowed_bindings() {
        let unrelated = scan(concat!(
            "from flask import Flask\n",
            "def make_app():\n",
            "    app = Flask(__name__)\n",
            "    return app\n",
            "@login_required\n",
            "@app.route('/x')\n",
            "def handler():\n",
            "    pass\n"
        ));
        assert!(findings(&unrelated, "python:S6552").is_empty());

        let parameter_shadow = scan(concat!(
            "from flask import Flask\n",
            "app = Flask(__name__)\n",
            "def outer(app):\n",
            "    @login_required\n",
            "    @app.route('/x')\n",
            "    def handler():\n",
            "        pass\n"
        ));
        assert!(findings(&parameter_shadow, "python:S6552").is_empty());
    }

    #[test]
    fn s6552_accepts_django_receiver_binding() {
        let flagged = scan(concat!(
            "from django.dispatch import receiver\n",
            "@other\n",
            "@receiver(signal)\n",
            "def handler(sender, **kwargs):\n",
            "    pass\n"
        ));
        assert_eq!(findings(&flagged, "python:S6552").len(), 1);
    }
}
