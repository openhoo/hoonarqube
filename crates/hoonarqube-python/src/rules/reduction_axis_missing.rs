use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::dotted_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

pub(crate) fn check_reduction_axis_missing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(path) = dotted_name(&call.func) else {
            continue;
        };
        if contains_spread_operator(call) {
            continue;
        }
        if is_tensorflow_reduction(call, &path, file_ctx)
            && !has_keyword(&call.arguments, "axis")
            && call.arguments.args.len() < 2
        {
            issues.push(issue_at(
                "python:S6929",
                "Specify the reduction axis explicitly.",
                call.range(),
                index,
                source,
            ));
        } else if is_pytorch_reduction_missing_dim(call, &path, file_ctx) {
            issues.push(issue_at(
                "python:S6929",
                "Provide a value for the dim argument.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn contains_spread_operator(call: &ExprCall) -> bool {
    call.arguments
        .args
        .iter()
        .any(|argument| matches!(argument, ruff_python_ast::Expr::Starred(_)))
        || call
            .arguments
            .keywords
            .iter()
            .any(|keyword| keyword.arg.is_none())
}

fn is_tensorflow_reduction(call: &ExprCall, path: &str, file_ctx: &FileContext) -> bool {
    let Some(resolved) = resolve_imported_path(file_ctx, path, call.range().start()) else {
        return false;
    };
    let Some(reduction) = resolved.rsplit('.').next() else {
        return false;
    };
    TF_REDUCTIONS.contains(&reduction)
        && (resolved == format!("tensorflow.math.{reduction}")
            || resolved == format!("tensorflow.tf.{reduction}")
            || resolved == format!("tensorflow.{reduction}"))
}

fn is_pytorch_reduction_missing_dim(call: &ExprCall, path: &str, file_ctx: &FileContext) -> bool {
    let Some(resolved) = resolve_imported_path(file_ctx, path, call.range().start()) else {
        return false;
    };
    let Some((_, position)) = PYTORCH_REDUCTIONS
        .iter()
        .find(|(function, _)| *function == resolved)
    else {
        return false;
    };
    call.arguments.find_keyword("dim").is_none()
        && (match usize::try_from(*position) {
            Ok(position) => call.arguments.find_positional(position).is_none(),
            Err(_) => true,
        })
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

// --- python:S6929 / python:S6925 — TensorFlow reduction/gather contracts -------------

const TF_REDUCTIONS: [&str; 11] = [
    "reduce_all",
    "reduce_mean",
    "reduce_any",
    "reduce_euclidean_norm",
    "reduce_logsumexp",
    "reduce_max",
    "reduce_min",
    "reduce_prod",
    "reduce_std",
    "reduce_sum",
    "reduce_variance",
];
const PYTORCH_REDUCTIONS: &[(&str, i32)] = &[
    ("torch.argmin", 1),
    ("torch.aminmax", -1),
    ("torch.nanmean", 1),
    ("torch.mode", 1),
    ("torch.norm", 2),
    ("torch.quantile", 2),
    ("torch.nanquantile", 2),
    ("torch.std", 1),
    ("torch.std_mean", 1),
    ("torch.unique", 4),
    ("torch.unique_consecutive", 3),
    ("torch.var", 1),
    ("torch.var_mean", 1),
    ("torch.count_nonzero", 1),
];

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6929_flags_imported_tensorflow_and_pytorch_reductions() {
        let flagged = scan(concat!(
            "import tensorflow as tf\n",
            "import torch\n",
            "tf.reduce_sum(values)\n",
            "tf.reduce_sum(values, axis=0)\n",
            "torch.argmin(values)\n",
            "torch.argmin(values, dim=0)\n"
        ));
        assert_eq!(findings(&flagged, "python:S6929").len(), 2);
    }
}
