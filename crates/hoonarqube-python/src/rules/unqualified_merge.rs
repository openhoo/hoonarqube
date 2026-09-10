use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

pub(crate) fn check_unqualified_merge(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(kind) = pandas_call_kind(call, file_ctx) else {
            continue;
        };
        let missing = missing_parameters(call, kind);
        if missing.is_empty() {
            continue;
        }
        let message = issue_message(kind, &missing);
        issues.push(issue_at(
            "python:S6735",
            &message,
            call.range(),
            index,
            source,
        ));
    }
    issues
}

#[derive(Clone, Copy)]
enum PandasCallKind {
    Join,
    DataFrameMerge,
    FreeMerge,
}

fn pandas_call_kind(call: &ExprCall, file_ctx: &FileContext) -> Option<PandasCallKind> {
    let path = dotted_name(&call.func)?;
    let at = call.range().start();
    if resolve_imported_path(file_ctx, &path, at).is_some_and(|resolved| {
        resolved == "pandas.merge" || resolved == "pandas.core.reshape.merge.merge"
    }) {
        return Some(PandasCallKind::FreeMerge);
    }
    let (root, method) = path.rsplit_once('.')?;
    if !matches!(method, "merge" | "join") || !dataframe_receiver(root, at, file_ctx) {
        return None;
    }
    Some(if method == "join" {
        PandasCallKind::Join
    } else {
        PandasCallKind::DataFrameMerge
    })
}

fn missing_parameters(call: &ExprCall, kind: PandasCallKind) -> Vec<&'static str> {
    let (how_position, on_position, left_on_position, right_on_position, validate_position) =
        match kind {
            PandasCallKind::Join => (2, 1, None, None, 6),
            PandasCallKind::DataFrameMerge => (1, 2, Some(3), Some(4), 11),
            PandasCallKind::FreeMerge => (2, 3, Some(4), Some(5), 12),
        };
    let has_how = argument_present(call, "how", how_position);
    let has_on = argument_present(call, "on", on_position);
    let has_left_on =
        left_on_position.is_some_and(|position| argument_present(call, "left_on", position));
    let has_right_on =
        right_on_position.is_some_and(|position| argument_present(call, "right_on", position));
    let has_validate = argument_present(call, "validate", validate_position);
    let cross_join = call
        .arguments
        .find_argument_value("how", how_position)
        .and_then(string_literal_value)
        .is_some_and(|value| value == "cross");

    let mut missing = Vec::new();
    if !has_how {
        missing.push("how");
    }
    if !cross_join && !has_on && !has_left_on && !has_right_on {
        missing.push("on");
    }
    if !has_validate {
        missing.push("validate");
    }
    missing
}

fn issue_message(kind: PandasCallKind, missing: &[&str]) -> String {
    let function = match kind {
        PandasCallKind::Join => "join",
        PandasCallKind::DataFrameMerge | PandasCallKind::FreeMerge => "merge",
    };
    match missing {
        [one] => format!("Specify the \"{one}\" parameter of this {function}."),
        [first, second] => {
            format!("Specify the \"{first}\" and \"{second}\" parameters of this {function}.")
        }
        [first, second, third] => format!(
            "Specify the \"{first}\", \"{second}\" and \"{third}\" parameters of this {function}."
        ),
        _ => format!("Specify the missing parameters of this {function}."),
    }
}

fn argument_present(call: &ExprCall, keyword: &str, position: usize) -> bool {
    call.arguments.find_keyword(keyword).is_some()
        || call.arguments.find_positional(position).is_some()
}

fn string_literal_value(expr: &Expr) -> Option<String> {
    let Expr::StringLiteral(literal) = expr else {
        return None;
    };
    Some(crate::support::string_value_text(&literal.value))
}

fn dataframe_receiver(root: &str, at: TextSize, file_ctx: &FileContext) -> bool {
    let Some((name, _)) = root.rsplit_once('.') else {
        return dataframe_binding(root, at, file_ctx);
    };
    dataframe_binding(name, at, file_ctx)
}

fn dataframe_binding(name: &str, at: TextSize, file_ctx: &FileContext) -> bool {
    let mut is_dataframe = false;
    for stmt in &file_ctx.stmts {
        if stmt.range().end() > at {
            continue;
        }
        let (targets, value) = match stmt {
            Stmt::Assign(assign) => {
                let mut targets = Vec::new();
                for target in &assign.targets {
                    collect_target_names(target, &mut targets);
                }
                (targets, Some(assign.value.as_ref()))
            }
            Stmt::AnnAssign(assign) => {
                let mut targets = Vec::new();
                collect_target_names(&assign.target, &mut targets);
                (
                    targets,
                    assign.value.as_ref().map(std::convert::AsRef::as_ref),
                )
            }
            _ => continue,
        };
        if targets.iter().any(|target| target == name) {
            is_dataframe = value.is_some_and(|value| is_dataframe_expression(value, at, file_ctx));
        }
    }
    is_dataframe
}

fn is_dataframe_expression(expr: &Expr, at: TextSize, file_ctx: &FileContext) -> bool {
    let Expr::Call(call) = expr else { return false };
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    let Some(resolved) = resolve_imported_path(file_ctx, &path, at) else {
        return false;
    };
    resolved == "pandas.DataFrame"
        || resolved == "pandas.core.frame.DataFrame"
        || (resolved.starts_with("pandas.")
            && matches!(
                resolved.rsplit('.').next(),
                Some(
                    "read_csv"
                        | "read_clipboard"
                        | "read_excel"
                        | "read_feather"
                        | "read_fwf"
                        | "read_hdf"
                        | "read_html"
                        | "read_json"
                        | "read_orc"
                        | "read_parquet"
                        | "read_pickle"
                        | "read_sql"
                        | "read_sql_query"
                        | "read_sql_table"
                        | "read_stata"
                        | "read_table"
                        | "read_xml"
                        | "json_normalize"
                        | "concat"
                        | "merge"
                )
            ))
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
    }) || file_ctx.functions.iter().any(|function| {
        let range = function.range();
        range.start() <= at
            && at <= range.end()
            && function
                .parameters
                .posonlyargs
                .iter()
                .chain(&function.parameters.args)
                .chain(&function.parameters.kwonlyargs)
                .any(|parameter| parameter.parameter.name.as_str() == bound)
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6735_requires_all_missing_merge_parameters() {
        let flagged = scan(concat!(
            "import pandas as pd\n",
            "left = pd.DataFrame()\n",
            "right = pd.DataFrame()\n",
            "left.merge(right)\n",
            "left.merge(right, on=\"k\")\n",
            "left.merge(right, how=\"cross\", validate=\"one_to_one\")\n"
        ));
        assert_eq!(findings(&flagged, "python:S6735").len(), 2);
    }
}
