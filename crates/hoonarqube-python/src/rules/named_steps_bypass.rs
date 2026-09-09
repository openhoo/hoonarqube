use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ExprCall;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

pub(crate) fn check_named_steps_bypass(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let mut issues = Vec::new();

    // Pinned SonarPython S6971 reports direct transformer uses in a cached
    // Pipeline. Work from FileContext's already-collected expressions/calls so
    // this pass neither reparses nor guesses from a method spelling.
    for call in &file_ctx.calls {
        if !is_pipeline_creation(call, file_ctx) || !has_known_memory(call) {
            continue;
        }
        let Some(steps) = call
            .arguments
            .find_keyword("steps")
            .map(|keyword| &keyword.value)
            .or_else(|| call.arguments.args.first())
        else {
            continue;
        };
        let Expr::List(list) = steps else { continue };
        for element in &list.elts {
            let Expr::Tuple(tuple) = element else {
                continue;
            };
            if tuple.elts.len() != 2 {
                continue;
            }
            let Expr::Name(transformer) = &tuple.elts[1] else {
                continue;
            };
            for expr in &file_ctx.exprs {
                let Expr::Attribute(attribute) = expr else {
                    continue;
                };
                let Some(root) = root_name(&attribute.value) else {
                    continue;
                };
                let root_overlaps_call = root.range().start() <= call.range().end();
                if root.id.as_str() != transformer.id.as_str()
                    || root_overlaps_call
                    || file_ctx.exprs.iter().any(|other| {
                        let Expr::Attribute(other_attribute) = other else {
                            return false;
                        };
                        let Some(other_root) = root_name(&other_attribute.value) else {
                            return false;
                        };
                        other_root.range() == root.range()
                            && other_attribute.range().end() > attribute.range().end()
                    })
                {
                    continue;
                }
                issues.push(issue_at(
                    "python:S6971",
                    "Avoid accessing transformers in a cached pipeline.",
                    root.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

fn root_name(expr: &Expr) -> Option<&ruff_python_ast::ExprName> {
    match expr {
        Expr::Name(name) => Some(name),
        Expr::Attribute(attribute) => root_name(&attribute.value),
        _ => None,
    }
}

fn is_pipeline_creation(call: &ExprCall, file_ctx: &FileContext) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    matches!(
        resolve_imported_path(file_ctx, &path, call.range().start()).as_deref(),
        Some("sklearn.pipeline.Pipeline" | "sklearn.pipeline.make_pipeline")
    )
}

fn has_known_memory(call: &ExprCall) -> bool {
    let Some(memory) = call.arguments.find_keyword("memory") else {
        return false;
    };
    matches!(
        &memory.value,
        Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::Call(_)
            | Expr::Dict(_)
            | Expr::List(_)
            | Expr::Tuple(_)
    )
}

fn dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attribute) => Some(format!(
            "{}.{}",
            dotted_name(&attribute.value)?,
            attribute.attr
        )),
        _ => None,
    }
}

fn resolve_imported_path(file_ctx: &FileContext, path: &str, at: TextSize) -> Option<String> {
    file_ctx
        .imports
        .iter()
        .filter_map(|entry| resolve_import_entry(file_ctx, path, at, entry))
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
        .map(|(_, resolved)| resolved)
}

fn choose_latest_candidate(
    best: Option<(TextSize, String)>,
    candidate: (TextSize, String),
) -> (TextSize, String) {
    match best {
        Some(previous) if candidate.0 <= previous.0 => previous,
        _ => candidate,
    }
}

fn resolve_import_entry(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    entry: &AnyImport<'_>,
) -> Option<(TextSize, String)> {
    match entry {
        AnyImport::Plain(import) => resolve_plain_import(file_ctx, path, at, import),
        AnyImport::From(import) => resolve_from_import(file_ctx, path, at, import),
    }
}

fn resolve_plain_import(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    import: &ruff_python_ast::StmtImport,
) -> Option<(TextSize, String)> {
    import
        .names
        .iter()
        .filter_map(|alias| {
            if alias.range.start() >= at {
                return None;
            }
            let full = alias.name.as_str();
            let bound = alias.asname.as_ref().map_or_else(
                || full.split('.').next().unwrap_or_default(),
                |name| name.as_str(),
            );
            let resolved = resolve_plain_path(path, full, bound)?;
            if import_binding_shadowed(file_ctx, bound, alias.range.end(), at) {
                return None;
            }
            Some((alias.range.start(), resolved))
        })
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
}

fn resolve_from_import(
    file_ctx: &FileContext,
    path: &str,
    at: TextSize,
    import: &ruff_python_ast::StmtImportFrom,
) -> Option<(TextSize, String)> {
    if import.level != 0 {
        return None;
    }
    let module = import.module.as_ref()?.as_str();
    import
        .names
        .iter()
        .filter_map(|alias| {
            if alias.range.start() >= at {
                return None;
            }
            let bound = alias
                .asname
                .as_ref()
                .map_or(alias.name.as_str(), |name| name.as_str());
            let resolved = resolve_from_path(path, module, alias.name.as_str(), bound)?;
            if import_binding_shadowed(file_ctx, bound, alias.range.end(), at) {
                return None;
            }
            Some((alias.range.start(), resolved))
        })
        .fold(None, |best, candidate| {
            Some(choose_latest_candidate(best, candidate))
        })
}

fn resolve_plain_path(path: &str, full: &str, bound: &str) -> Option<String> {
    if path == full || path.starts_with(&format!("{full}.")) {
        return Some(path.to_string());
    }
    if path == bound {
        return Some(full.to_string());
    }
    let suffix = path.strip_prefix(&format!("{bound}."))?;
    Some(format!("{full}.{suffix}"))
}

fn resolve_from_path(path: &str, module: &str, imported: &str, bound: &str) -> Option<String> {
    if path == bound {
        return Some(format!("{module}.{imported}"));
    }
    let suffix = path.strip_prefix(&format!("{bound}."))?;
    Some(format!("{module}.{imported}.{suffix}"))
}

fn import_binding_shadowed(
    file_ctx: &FileContext,
    bound: &str,
    import_end: TextSize,
    at: TextSize,
) -> bool {
    file_ctx.stmts.iter().any(|stmt| {
        let range = stmt.range();
        if range.start() <= import_end || range.start() >= at {
            return false;
        }
        let mut names = Vec::new();
        match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_target_names(target, &mut names);
                }
            }
            Stmt::AnnAssign(assign) => collect_target_names(&assign.target, &mut names),
            Stmt::For(for_stmt) => collect_target_names(&for_stmt.target, &mut names),
            _ => {}
        }
        names.iter().any(|name| name == bound)
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6971_flags_direct_transformer_use_in_cached_pipeline() {
        let flagged = scan(concat!(
            "from sklearn.pipeline import Pipeline\n",
            "transformer = object()\n",
            "pipe = Pipeline([(\"scale\", transformer)], memory=\"./c\")\n",
            "transformer.fit(data)\n"
        ));
        assert_eq!(findings(&flagged, "python:S6971").len(), 1);
    }
}
