use super::{Alternative, alt, issue_range, text_edit};
use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::{
    ROUTE_DECORATOR_TAILS, child_bodies, decorator_callee_path, dotted_name, for_each_expr,
    for_each_stmt_in_scope, is_super_init_call, stmt_exprs, stmt_store_names,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, UnaryOp};
use ruff_python_parser::Parsed;
use ruff_source_file::{LineIndex, LineRanges};
use ruff_text_size::{Ranged, TextRange, TextSize};

/// Returns all pinned `SonarPython` alternatives owned by the type/framework
/// family. The detector retains ownership of whether an issue exists; every
/// candidate below is additionally tied to the exact AST node that produced it.
pub(super) fn alternatives(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    match issue.rule_key.as_str() {
        "python:S6538" => s6538(parsed, index, source, file_ctx, issue),
        "python:S6545" => s6545(parsed, index, source, file_ctx, issue),
        "python:S6552" => s6552(parsed, index, source, file_ctx, issue),
        "python:S6978" => s6978(parsed, index, source, file_ctx, issue),
        "python:S7500" => s7500(index, source, file_ctx, issue),
        _ => Vec::new(),
    }
}

fn s6538(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(function) = file_ctx
        .functions
        .iter()
        .copied()
        .find(|function| function.name.range() == issue_span)
    else {
        return Vec::new();
    };
    if function.returns.is_some() {
        return Vec::new();
    }

    let annotation = if function.name.as_str() == "__init__"
        && file_ctx
            .classes
            .iter()
            .any(|class| class_contains_method(class, function.range()))
    {
        Some("None")
    } else {
        infer_return_annotation(function)
    };
    let Some(annotation) = annotation else {
        return Vec::new();
    };

    let insertion = function.parameters.range().end();
    if insertion.to_usize() > source.len() {
        return Vec::new();
    }
    // `parsed` is part of the module contract and also ensures this helper
    // never fabricates a function from an issue range outside the parsed AST.
    if !parsed.syntax().range().contains_range(function.range()) {
        return Vec::new();
    }
    vec![alt(
        "s6538-add-return-type",
        "Add a return type hint to this function declaration.",
        vec![text_edit(
            index,
            source,
            TextRange::new(insertion, insertion),
            format!(" -> {annotation}"),
        )],
    )]
}

fn infer_return_annotation(function: &ruff_python_ast::StmtFunctionDef) -> Option<&'static str> {
    let mut saw_return = false;
    let mut saw_yield = false;
    let mut unsupported = false;
    let mut inferred = None;

    for_each_stmt_in_scope(function.body.as_slice(), &mut |statement| {
        if let Stmt::Return(return_stmt) = statement {
            saw_return = true;
            if let Some(value) = return_stmt.value.as_deref() {
                let Some(annotation) = literal_return_annotation(value) else {
                    unsupported = true;
                    return;
                };
                if inferred.is_some_and(|previous| previous != annotation) {
                    unsupported = true;
                } else {
                    inferred = Some(annotation);
                }
            }
        }
        for expression in stmt_exprs(statement) {
            for_each_expr(expression, &mut |expression| {
                saw_yield |= matches!(expression, Expr::Yield(_) | Expr::YieldFrom(_));
            });
        }
    });

    if saw_yield || unsupported {
        return None;
    }
    if saw_return {
        // Upstream has no suggestion for a function containing only bare
        // returns; a bare return contributes no supported type evidence.
        inferred
    } else {
        Some("None")
    }
}

fn literal_return_annotation(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::NoneLiteral(_) => Some("None"),
        Expr::BooleanLiteral(_) => Some("bool"),
        Expr::StringLiteral(_) => Some("str"),
        Expr::NumberLiteral(number) => Some(match &number.value {
            ruff_python_ast::Number::Int(_) => "int",
            ruff_python_ast::Number::Float(_) => "float",
            ruff_python_ast::Number::Complex { .. } => "complex",
        }),
        Expr::UnaryOp(unary) if matches!(unary.op, UnaryOp::UAdd | UnaryOp::USub) => {
            literal_return_annotation(&unary.operand)
        }
        _ => None,
    }
}

fn class_contains_method(class: &ruff_python_ast::StmtClassDef, function_range: TextRange) -> bool {
    class_body_contains_method(class.body.as_slice(), function_range)
}

fn class_body_contains_method(body: &[Stmt], function_range: TextRange) -> bool {
    for statement in body {
        match statement {
            Stmt::FunctionDef(function) if function.range() == function_range => return true,
            // A nested function or class starts a new lexical scope and cannot
            // be the instance method of this class.
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            _ => {
                if child_bodies(statement)
                    .into_iter()
                    .any(|child| class_body_contains_method(child, function_range))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn s6545(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(subscript) = file_ctx.exprs.iter().copied().find_map(|expression| {
        let Expr::Subscript(subscript) = expression else {
            return None;
        };
        (subscript.value.range() == issue_span).then_some(subscript)
    }) else {
        return Vec::new();
    };
    let Some(replacement) = typing_alias_replacement(parsed, file_ctx, subscript.value.as_ref())
    else {
        return Vec::new();
    };
    vec![alt(
        "s6545-use-builtin-generic",
        "Use builtin generics instead of the typing alias.",
        vec![text_edit(
            index,
            source,
            subscript.value.range(),
            replacement,
        )],
    )]
}

fn builtin_generic(name: &str) -> Option<&'static str> {
    match name {
        "List" => Some("list"),
        "Dict" => Some("dict"),
        "Set" => Some("set"),
        "Tuple" => Some("tuple"),
        "FrozenSet" => Some("frozenset"),
        "Type" => Some("type"),
        _ => None,
    }
}

fn typing_alias_replacement(
    parsed: &Parsed<ModModule>,
    file_ctx: &FileContext<'_>,
    value: &Expr,
) -> Option<String> {
    let root = parsed.syntax().range();
    let target_range = value.range();
    let current_scope = scope_for(parsed.syntax().body.as_slice(), root, target_range);

    match value {
        Expr::Name(name) => {
            let candidate = file_ctx.imports.iter().filter_map(|entry| {
                let AnyImport::From(import) = entry else {
                    return None;
                };
                if import.level != 0
                    || import
                        .module
                        .as_ref()
                        .map(ruff_python_ast::Identifier::as_str)
                        != Some("typing")
                {
                    return None;
                }
                import.names.iter().find_map(|alias| {
                    let local = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str);
                    let replacement = builtin_generic(alias.name.as_str())?;
                    (local == name.id.as_str() && alias.range().end() <= target_range.start())
                        .then_some((alias.range(), replacement))
                })
            });
            let (binding, replacement) =
                latest_visible_import(candidate, current_scope, parsed, target_range.start())?;
            (!has_shadowing(
                current_scope,
                name.id.as_str(),
                target_range.start(),
                binding,
            ))
            .then_some(replacement.to_string())
        }
        Expr::Attribute(attribute) => {
            let replacement = builtin_generic(attribute.attr.as_str())?;
            let Expr::Name(root_name) = attribute.value.as_ref() else {
                return None;
            };
            let candidate = file_ctx.imports.iter().filter_map(|entry| {
                let AnyImport::Plain(import) = entry else {
                    return None;
                };
                import.names.iter().find_map(|alias| {
                    let local = alias.asname.as_ref().map_or_else(
                        || alias.name.as_str().split('.').next().unwrap_or(""),
                        ruff_python_ast::Identifier::as_str,
                    );
                    (alias.name.as_str() == "typing"
                        && local == root_name.id.as_str()
                        && alias.range().end() <= target_range.start())
                    .then_some((alias.range(), replacement))
                })
            });
            let (binding, _) =
                latest_visible_import(candidate, current_scope, parsed, target_range.start())?;
            (!has_shadowing(
                current_scope,
                root_name.id.as_str(),
                target_range.start(),
                binding,
            ))
            .then_some(replacement.to_string())
        }
        _ => None,
    }
}

fn latest_visible_import(
    candidates: impl Iterator<Item = (TextRange, &'static str)>,
    current_scope: LexicalScope<'_>,
    parsed: &Parsed<ModModule>,
    before: TextSize,
) -> Option<(TextRange, &'static str)> {
    candidates
        .filter(|(candidate, _)| {
            let candidate_scope = scope_for(
                parsed.syntax().body.as_slice(),
                parsed.syntax().range(),
                *candidate,
            );
            import_scope_visible(current_scope, candidate_scope) && candidate.end() <= before
        })
        .max_by_key(|(candidate, _)| candidate.start())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
}

#[derive(Clone, Copy)]
struct LexicalScope<'a> {
    body: &'a [Stmt],
    key: TextRange,
    kind: ScopeKind,
    function: Option<&'a ruff_python_ast::StmtFunctionDef>,
}

fn scope_for(body: &[Stmt], module_range: TextRange, target: TextRange) -> LexicalScope<'_> {
    descend_scope(
        body,
        target,
        LexicalScope {
            body,
            key: module_range,
            kind: ScopeKind::Module,
            function: None,
        },
    )
}

fn descend_scope<'a>(
    body: &'a [Stmt],
    target: TextRange,
    current: LexicalScope<'a>,
) -> LexicalScope<'a> {
    for statement in body {
        if let Some(found) = descend_scope_statement(statement, target, current) {
            return found;
        }
    }
    current
}

fn descend_scope_statement<'a>(
    statement: &'a Stmt,
    target: TextRange,
    current: LexicalScope<'a>,
) -> Option<LexicalScope<'a>> {
    if !contains_range(statement.range(), target) {
        return None;
    }
    match statement {
        Stmt::FunctionDef(function) => {
            let body_range = suite_range(function.body.as_slice(), function.range());
            contains_range(body_range, target).then(|| {
                descend_scope(
                    function.body.as_slice(),
                    target,
                    LexicalScope {
                        body: function.body.as_slice(),
                        key: body_range,
                        kind: ScopeKind::Function,
                        function: Some(function),
                    },
                )
            })
        }
        Stmt::ClassDef(class) => {
            let body_range = suite_range(class.body.as_slice(), class.range());
            contains_range(body_range, target).then(|| {
                descend_scope(
                    class.body.as_slice(),
                    target,
                    LexicalScope {
                        body: class.body.as_slice(),
                        key: body_range,
                        kind: ScopeKind::Class,
                        function: None,
                    },
                )
            })
        }
        _ => {
            for child in child_bodies(statement) {
                let Some((first, last)) = child.first().zip(child.last()) else {
                    continue;
                };
                if contains_range(TextRange::new(first.start(), last.end()), target) {
                    return Some(descend_scope(child, target, current));
                }
            }
            None
        }
    }
}

fn suite_range(body: &[Stmt], fallback: TextRange) -> TextRange {
    body.first()
        .zip(body.last())
        .map_or(fallback, |(first, last)| {
            TextRange::new(first.start(), last.end())
        })
}

fn contains_range(outer: TextRange, inner: TextRange) -> bool {
    outer.start() <= inner.start() && inner.end() <= outer.end()
}

fn import_scope_visible(current: LexicalScope<'_>, candidate: LexicalScope<'_>) -> bool {
    current.key == candidate.key
        || (candidate.kind != ScopeKind::Class && contains_range(candidate.key, current.key))
}

fn has_shadowing(
    scope: LexicalScope<'_>,
    name: &str,
    before: TextSize,
    source_import: TextRange,
) -> bool {
    if scope.kind == ScopeKind::Function
        && scope.function.is_some_and(|function| {
            function
                .parameters
                .iter()
                .any(|parameter| parameter.name().as_str() == name)
        })
    {
        return true;
    }

    let mut shadowed = false;
    for_each_stmt_in_scope(scope.body, &mut |statement| {
        if shadowed
            || !stmt_store_names(statement)
                .iter()
                .any(|stored| stored == name)
        {
            return;
        }
        if statement_imports_range(statement, source_import) {
            return;
        }
        shadowed = match scope.kind {
            ScopeKind::Function => true,
            ScopeKind::Module | ScopeKind::Class => statement.range().start() < before,
        };
    });
    shadowed
}

fn statement_imports_range(statement: &Stmt, range: TextRange) -> bool {
    match statement {
        Stmt::Import(import) => import.names.iter().any(|alias| alias.range() == range),
        Stmt::ImportFrom(import) => import.names.iter().any(|alias| alias.range() == range),
        _ => false,
    }
}

fn s6552(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((function, position, decorator)) = file_ctx.functions.iter().find_map(|function| {
        function
            .decorator_list
            .iter()
            .enumerate()
            .find_map(|(position, decorator)| {
                (decorator.expression.range() == issue_span)
                    .then_some((function, position, decorator))
            })
    }) else {
        return Vec::new();
    };
    if position == 0 {
        return Vec::new();
    }
    let Some(tail) = decorator_callee_path(&decorator.expression)
        .and_then(|path| path.rsplit('.').next().map(str::to_string))
    else {
        return Vec::new();
    };
    if !ROUTE_DECORATOR_TAILS.contains(&tail.as_str()) {
        return Vec::new();
    }
    let Some(first_decorator) = function.decorator_list.first() else {
        return Vec::new();
    };

    let route_line_start = source.line_start(decorator.range.start());
    let route_line_end = source.full_line_end(decorator.range.start());
    let first_line_start = source.line_start(first_decorator.range.start());
    if route_line_start <= first_line_start {
        return Vec::new();
    }
    let route_line = source[TextRange::new(route_line_start, route_line_end)].to_string();
    vec![alt(
        "s6552-move-decorator",
        format!("Move the '@{tail}' decorator to the top"),
        vec![
            text_edit(
                index,
                source,
                TextRange::new(first_line_start, first_line_start),
                route_line,
            ),
            text_edit(
                index,
                source,
                TextRange::new(route_line_start, route_line_end),
                "",
            ),
        ],
    )]
}

fn s6978(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(class) = file_ctx
        .classes
        .iter()
        .copied()
        .find(|class| class.name.range() == issue_span)
    else {
        return Vec::new();
    };
    if !torch_module_base_is_bound(class, file_ctx) {
        return Vec::new();
    }
    let Some(function) = class.body.iter().find_map(|statement| match statement {
        Stmt::FunctionDef(function) if function.name.as_str() == "__init__" => Some(function),
        _ => None,
    }) else {
        return Vec::new();
    };
    let mut super_called = false;
    for_each_stmt_in_scope(function.body.as_slice(), &mut |statement| {
        for expression in stmt_exprs(statement) {
            for_each_expr(expression, &mut |expression| {
                super_called |= is_super_init_call(expression);
            });
        }
    });
    if super_called {
        return Vec::new();
    }
    let Some(first) = function.body.first() else {
        return Vec::new();
    };
    let function_line = source.line_start(function.range().start());
    let first_line = source.line_start(first.range().start());
    if function_line == first_line {
        // The pinned implementation deliberately avoids one-line bodies: its
        // line insertion helper cannot infer a safe indentation there.
        return Vec::new();
    }
    let line_start = source.line_start(first.range().start());
    let line_end = source.line_end(first.range().start());
    let full_end = source.full_line_end(first.range().start());
    let indentation = &source[TextRange::new(line_start, first.range().start())];
    if !indentation.chars().all(char::is_whitespace) {
        return Vec::new();
    }
    let newline = if source[TextRange::new(line_end, full_end)].starts_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    if !parsed.syntax().range().contains_range(class.range()) {
        return Vec::new();
    }
    vec![alt(
        "s6978-insert-super-init",
        "insert call to super constructor",
        vec![text_edit(
            index,
            source,
            TextRange::new(line_start, line_start),
            format!("{indentation}super().__init__(){newline}"),
        )],
    )]
}

fn torch_module_base_is_bound(
    class: &ruff_python_ast::StmtClassDef,
    file_ctx: &FileContext<'_>,
) -> bool {
    class.bases().iter().any(|base| {
        let Some(path) = dotted_name(base) else {
            return false;
        };
        file_ctx.imports.iter().any(|entry| match entry {
            AnyImport::Plain(import) => import.names.iter().any(|alias| {
                let local = alias.asname.as_ref().map_or_else(
                    || alias.name.as_str().split('.').next().unwrap_or(""),
                    ruff_python_ast::Identifier::as_str,
                );
                alias.range().end() <= class.range().start()
                    && ((alias.name.as_str() == "torch"
                        && (path == format!("{local}.nn.Module")
                            || path == format!("{local}.nn.modules.module.Module")))
                        || (alias.name.as_str() == "torch.nn"
                            && if alias.asname.is_some() {
                                path == format!("{local}.Module")
                            } else {
                                path == "torch.nn.Module"
                                    || path == "torch.nn.modules.module.Module"
                            })
                        || (alias.name.as_str() == "torch.nn.modules.module"
                            && path == format!("{local}.Module")))
            }),
            AnyImport::From(import) => {
                let module = import
                    .module
                    .as_ref()
                    .map(ruff_python_ast::Identifier::as_str);
                import.names.iter().any(|alias| {
                    let local = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), ruff_python_ast::Identifier::as_str);
                    alias.range().end() <= class.range().start()
                        && ((module == Some("torch")
                            && alias.name.as_str() == "nn"
                            && path == format!("{local}.Module"))
                            || (matches!(module, Some("torch.nn" | "torch.nn.modules.module"))
                                && alias.name.as_str() == "Module"
                                && path == local))
                })
            }
        })
    })
}

fn s7500(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((kind, iterable)) = file_ctx.exprs.iter().find_map(|expression| {
        if expression.range() != issue_span {
            return None;
        }
        match expression {
            Expr::ListComp(comp) => {
                let generator = sole_simple_generator(&comp.generators)?;
                same_name(&comp.elt, &generator.target)
                    .then_some((CollectionKind::List, &generator.iter))
            }
            Expr::SetComp(comp) => {
                let generator = sole_simple_generator(&comp.generators)?;
                same_name(&comp.elt, &generator.target)
                    .then_some((CollectionKind::Set, &generator.iter))
            }
            Expr::Generator(comp) => {
                let generator = sole_simple_generator(&comp.generators)?;
                same_name(&comp.elt, &generator.target)
                    .then_some((CollectionKind::Generator, &generator.iter))
            }
            Expr::DictComp(comp) => {
                let generator = sole_simple_generator(&comp.generators)?;
                let key = comp.key.as_deref()?;
                let Expr::Tuple(target) = &generator.target else {
                    return None;
                };
                let [target_key, target_value] = target.elts.as_slice() else {
                    return None;
                };
                same_name(key, target_key)
                    .then(|| same_name(&comp.value, target_value))
                    .filter(|same| *same)
                    .map(|_| (CollectionKind::Dict, &generator.iter))
            }
            _ => None,
        }
    }) else {
        return Vec::new();
    };
    if !contains_range(issue_span, iterable.range()) {
        return Vec::new();
    }
    let iterable_text = source[iterable.range()].to_string();
    let replacement = match kind {
        CollectionKind::Generator => iterable_text,
        CollectionKind::List => format!("list({iterable_text})"),
        CollectionKind::Set => format!("set({iterable_text})"),
        CollectionKind::Dict => format!("dict({iterable_text})"),
    };
    vec![alt(
        "s7500-use-constructor",
        "Replace with collection constructor call",
        vec![text_edit(index, source, issue_span, replacement)],
    )]
}

#[derive(Clone, Copy)]
enum CollectionKind {
    Generator,
    List,
    Set,
    Dict,
}

fn sole_simple_generator(
    generators: &[ruff_python_ast::Comprehension],
) -> Option<&ruff_python_ast::Comprehension> {
    let [generator] = generators else {
        return None;
    };
    (generator.ifs.is_empty() && !generator.is_async).then_some(generator)
}

fn same_name(left: &Expr, right: &Expr) -> bool {
    matches!((left, right), (Expr::Name(left), Expr::Name(right)) if left.id == right.id)
}
