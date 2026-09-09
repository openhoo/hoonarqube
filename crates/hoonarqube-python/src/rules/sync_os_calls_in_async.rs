use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ExprCall, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

const OS_WAIT_CALLS: &[&str] = &["wait", "waitpid", "waitid"];

pub(crate) fn check_sync_os_calls_in_async(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !is_os_wait_call(call, file_ctx) {
            continue;
        }
        let Some(function) = file_ctx
            .functions
            .iter()
            .filter_map(|function| {
                let first = function.body.first()?;
                let last = function.body.last()?;
                let body_range = TextRange::new(first.range().start(), last.range().end());
                body_range
                    .contains_range(call.range())
                    .then_some((function, body_range.len()))
            })
            .min_by_key(|(_, length)| *length)
            .map(|(function, _)| function)
        else {
            continue;
        };
        if !function.is_async {
            continue;
        }
        issues.push(issue_at(
            "python:S7489",
            "Use a thread executor to wrap blocking OS calls in this async function.",
            call.range(),
            index,
            source,
        ));
    }
    issues
}

fn is_os_wait_call(call: &ExprCall, file_ctx: &FileContext) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    let Some(resolved) = resolve_imported_path(file_ctx, &path, call.range().start()) else {
        return false;
    };
    let Some(method) = resolved.strip_prefix("os.") else {
        return false;
    };
    OS_WAIT_CALLS.contains(&method)
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
    fn s7489_flags_imported_os_wait_calls_in_async_functions() {
        let flagged = scan(concat!(
            "import os as operating_system\n",
            "from os import wait as wait_for\n",
            "async def sh():\n",
            "    operating_system.wait()\n",
            "    wait_for()\n",
            "    fake.wait()\n"
        ));
        assert_eq!(findings(&flagged, "python:S7489").len(), 2);
    }
}
