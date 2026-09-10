use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::{
    collect_target_names, dotted_name, named_parameters, string_value_text, to_u32,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::{LineIndex, LineRanges};
use ruff_text_size::{Ranged, TextRange, TextSize};

use super::{Alternative, alt, issue_range, text_edit};

const S5915_RAISE_METHODS: &[&str] = &["assertRaises", "assertRaisesRegex", "assertRaisesRegexp"];
const S5915_ASSERT_METHODS: &[&str] = &[
    "assertEqual",
    "assertNotEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIsNot",
    "assertIsNone",
    "assertIsNotNone",
    "assertIn",
    "assertNotIn",
    "assertIsInstance",
    "assertNotIsInstance",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "assertRegex",
    "assertNotRegex",
    "assertCountEqual",
    "assertMultiLineEqual",
    "assertSequenceEqual",
    "assertListEqual",
    "assertTupleEqual",
    "assertSetEqual",
    "assertDictEqual",
    "assertDictContainsSubset",
    "assertWarns",
    "assertWarnsRegex",
    "assertLogs",
    "assertNoLogs",
    "assertRaises",
    "assertRaisesRegex",
    "assertRaisesRegexp",
];
const S6929_REDUCTIONS: &[&str] = &[
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
const S7489_OS_CALLS: &[&str] = &["wait", "waitpid", "waitid"];

/// Detector-time alternatives for framework rules whose upstream fixes use
/// semantic library identities. The detector remains responsible for finding
/// issues; this post-pass only offers an edit after proving the import and AST
/// shape from the existing `FileContext`.
pub(super) fn alternatives(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let _ = parsed;
    match issue.rule_key.as_str() {
        "python:S5915" => s5915(index, source, file_ctx, issue),
        "python:S6735" => s6735(index, source, file_ctx, issue),
        "python:S6929" => s6929(index, source, file_ctx, issue),
        "python:S6969" => s6969(index, source, file_ctx, issue),
        "python:S6971" => s6971(index, source, file_ctx, issue),
        "python:S7489" => s7489(index, source, file_ctx, issue),
        _ => Vec::new(),
    }
}

fn s5915(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((with_stmt, statement)) = file_ctx.stmts.iter().find_map(|stmt| {
        let Stmt::With(with_stmt) = stmt else {
            return None;
        };
        let statement = with_stmt.body.last()?;
        (statement.range() == issue_span
            && with_stmt.body.len() > 1
            && with_stmt.items.iter().any(|item| {
                let Expr::Call(call) = &item.context_expr else {
                    return false;
                };
                is_pytest_raise(call, file_ctx) || is_unittest_raise(call)
            }))
        .then_some((with_stmt, statement))
    }) else {
        return Vec::new();
    };

    if !is_assert_statement(statement) {
        return Vec::new();
    }

    let statement_start = statement.range().start();
    let with_start = with_stmt.range().start();
    let statement_line = source.line_start(statement_start);
    let with_line = source.line_start(with_start);
    let edits = if statement_line == with_line {
        let indent = with_start.to_usize().saturating_sub(with_line.to_usize());
        vec![text_edit(
            index,
            source,
            TextRange::empty(statement_start),
            format!("\n{}", " ".repeat(indent)),
        )]
    } else {
        let with_column = with_start.to_usize().saturating_sub(with_line.to_usize());
        let statement_column = statement_start
            .to_usize()
            .saturating_sub(statement_line.to_usize());
        let amount = statement_column.saturating_sub(with_column);
        if amount == 0 {
            return Vec::new();
        }
        shift_left_edits(index, source, statement.range(), amount)
    };

    if edits.is_empty() {
        return Vec::new();
    }
    vec![alt(
        "s5915-change-indentation-level",
        "Change indentation level",
        edits,
    )]
}

fn is_assert_statement(statement: &Stmt) -> bool {
    if matches!(statement, Stmt::Assert(_)) {
        return true;
    }
    let Stmt::Expr(expression) = statement else {
        return false;
    };
    let Expr::Call(call) = expression.value.as_ref() else {
        return false;
    };
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
        && S5915_ASSERT_METHODS.contains(&attribute.attr.as_str())
}

fn is_pytest_raise(call: &ExprCall, file_ctx: &FileContext<'_>) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    if resolve_imported_path(file_ctx, &path, call.range().start()).as_deref()
        != Some("pytest.raises")
    {
        return false;
    }
    let Some(expected) = first_argument_or_keyword(call, "expected_exception") else {
        return false;
    };
    !is_assertion_error(expected)
}

fn is_unittest_raise(call: &ExprCall) -> bool {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return false;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return false;
    };
    receiver.id.as_str() == "self"
        && S5915_RAISE_METHODS.contains(&attribute.attr.as_str())
        && first_argument_or_keyword(call, "exception")
            .is_some_and(|expected| !is_assertion_error(expected))
}

fn is_assertion_error(expr: &Expr) -> bool {
    matches!(
        dotted_name(expr).as_deref(),
        Some("AssertionError" | "builtins.AssertionError")
    )
}

fn first_argument_or_keyword<'a>(call: &'a ExprCall, keyword: &str) -> Option<&'a Expr> {
    call.arguments
        .find_keyword(keyword)
        .map(|keyword| &keyword.value)
        .or_else(|| call.arguments.args.first())
}

fn s6735(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(call) = find_call(file_ctx, issue_span) else {
        return Vec::new();
    };
    let Some(kind) = pandas_call_kind(call, file_ctx) else {
        return Vec::new();
    };
    if call.arguments.is_empty() || has_variadic_argument(call) {
        return Vec::new();
    }

    let (
        how_position,
        on_position,
        left_on_position,
        right_on_position,
        validate_position,
        default_how,
    ) = match kind {
        PandasCallKind::DataFrameJoin => (2, 1, None, None, 6, "left"),
        PandasCallKind::DataFrameMerge => (1, 2, Some(3), Some(4), 11, "inner"),
        PandasCallKind::PandasMerge => (2, 3, Some(4), Some(5), 12, "inner"),
    };
    let has_how = argument_present(call, "how", how_position);
    let has_on = argument_present(call, "on", on_position);
    let has_left_on =
        left_on_position.is_some_and(|position| argument_present(call, "left_on", position));
    let has_right_on =
        right_on_position.is_some_and(|position| argument_present(call, "right_on", position));
    let is_cross_join = call
        .arguments
        .find_argument_value("how", how_position)
        .and_then(string_literal_value)
        .is_some_and(|value| value == "cross");
    let has_validate = argument_present(call, "validate", validate_position);

    let mut missing = Vec::new();
    if !has_how {
        missing.push(format!("how=\"{default_how}\""));
    }
    if !is_cross_join && !has_on && !has_left_on && !has_right_on {
        missing.push("on=None".to_string());
    }
    if !has_validate {
        missing.push("validate=\"many_to_many\"".to_string());
    }
    if missing.is_empty() {
        return Vec::new();
    }

    vec![alt(
        "s6735-add-merge-parameters",
        "Add the missing parameters",
        vec![insert_before_closing_par(
            index,
            source,
            call,
            &format!(", {}", missing.join(", ")),
        )],
    )]
}

#[derive(Clone, Copy)]
enum PandasCallKind {
    DataFrameJoin,
    DataFrameMerge,
    PandasMerge,
}

fn pandas_call_kind(call: &ExprCall, file_ctx: &FileContext<'_>) -> Option<PandasCallKind> {
    let path = dotted_name(&call.func)?;
    let at = call.range().start();
    let resolved = resolve_imported_path(file_ctx, &path, at);
    if resolved.as_deref().is_some_and(|resolved| {
        resolved == "pandas.merge" || resolved == "pandas.core.reshape.merge.merge"
    }) {
        return Some(PandasCallKind::PandasMerge);
    }
    let (root, method) = path.rsplit_once('.')?;
    if !matches!(method, "merge" | "join") || !dataframe_receiver(root, at, file_ctx) {
        return None;
    }
    Some(if method == "join" {
        PandasCallKind::DataFrameJoin
    } else {
        PandasCallKind::DataFrameMerge
    })
}

fn argument_present(call: &ExprCall, keyword: &str, position: usize) -> bool {
    call.arguments.find_keyword(keyword).is_some()
        || call.arguments.find_positional(position).is_some()
}

fn string_literal_value(expr: &Expr) -> Option<String> {
    let Expr::StringLiteral(literal) = expr else {
        return None;
    };
    Some(string_value_text(&literal.value))
}

fn dataframe_receiver(root: &str, at: TextSize, file_ctx: &FileContext<'_>) -> bool {
    let Some((name, _)) = root.rsplit_once('.') else {
        return dataframe_binding(root, at, file_ctx);
    };
    dataframe_binding(name, at, file_ctx)
}

fn dataframe_binding(name: &str, at: TextSize, file_ctx: &FileContext<'_>) -> bool {
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
                (targets, assign.value.as_deref())
            }
            _ => continue,
        };
        if targets.iter().any(|target| target == name) {
            is_dataframe = value.is_some_and(|value| is_dataframe_expression(value, at, file_ctx));
        }
    }
    is_dataframe
}

fn is_dataframe_expression(expr: &Expr, at: TextSize, file_ctx: &FileContext<'_>) -> bool {
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

fn s6929(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(call) = find_call(file_ctx, issue_span) else {
        return Vec::new();
    };
    if call.arguments.is_empty() || has_variadic_argument(call) {
        return Vec::new();
    }
    let Some(path) = dotted_name(&call.func) else {
        return Vec::new();
    };
    let Some(reduction) = path.rsplit('.').next() else {
        return Vec::new();
    };
    if !S6929_REDUCTIONS.contains(&reduction)
        || !is_tensorflow_reduction(&path, call.range().start(), file_ctx)
        || call.arguments.find_argument_value("axis", 1).is_some()
    {
        return Vec::new();
    }
    vec![alt(
        "s6929-add-axis-parameter",
        "Add axis parameter",
        vec![insert_before_closing_par(
            index,
            source,
            call,
            ", axis=None",
        )],
    )]
}

fn is_tensorflow_reduction(path: &str, at: TextSize, file_ctx: &FileContext<'_>) -> bool {
    let Some(resolved) = resolve_imported_path(file_ctx, path, at) else {
        return false;
    };
    let Some(reduction) = path.rsplit('.').next() else {
        return false;
    };
    let canonical = format!("tensorflow.math.{reduction}");
    resolved == canonical
        || resolved == format!("tensorflow.tf.{reduction}")
        || resolved == format!("tensorflow.{reduction}")
}

fn s6969(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(call) = find_call(file_ctx, issue_span) else {
        return Vec::new();
    };
    if has_variadic_argument(call) || call.arguments.is_empty() {
        return Vec::new();
    }
    if !sklearn_pipeline_call(call, file_ctx, call.range().start()) {
        return Vec::new();
    }
    if pipeline_used_by_another_pipeline(call, file_ctx) {
        return Vec::new();
    }
    vec![alt(
        "s6969-add-memory-argument",
        "Add the memory argument",
        vec![insert_before_closing_par(
            index,
            source,
            call,
            ", memory=None",
        )],
    )]
}

fn sklearn_pipeline_call(call: &ExprCall, file_ctx: &FileContext<'_>, at: TextSize) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    matches!(
        resolve_imported_path(file_ctx, &path, at).as_deref(),
        Some("sklearn.pipeline.Pipeline" | "sklearn.pipeline.make_pipeline")
    )
}

fn pipeline_used_by_another_pipeline(call: &ExprCall, file_ctx: &FileContext<'_>) -> bool {
    let Some(assignment_name) = assigned_name_for_call(call, file_ctx) else {
        return false;
    };
    file_ctx.exprs.iter().any(|expr| {
        let Expr::Name(name) = expr else { return false };
        name.id.as_str() == assignment_name
            && expr.range().start() > call.range().end()
            && file_ctx.calls.iter().any(|outer| {
                outer.range().contains_range(expr.range())
                    && outer.range() != call.range()
                    && (sklearn_pipeline_call(outer, file_ctx, outer.range().start())
                        || sklearn_compose_call(outer, file_ctx, outer.range().start()))
            })
    })
}

fn sklearn_compose_call(call: &ExprCall, file_ctx: &FileContext<'_>, at: TextSize) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    resolve_imported_path(file_ctx, &path, at)
        .is_some_and(|resolved| resolved.starts_with("sklearn.compose."))
}

fn s6971(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((transformer, use_span)) = file_ctx.exprs.iter().find_map(|expr| {
        let Expr::Attribute(attribute) = expr else {
            return None;
        };
        let root = root_name(&attribute.value)?;
        (root.range() == issue_span).then_some((root.id.as_str(), root.range()))
    }) else {
        return Vec::new();
    };

    let mut candidates = file_ctx.calls.iter().filter_map(|call| {
        if !sklearn_pipeline_call(call, file_ctx, call.range().start()) {
            return None;
        }
        let memory = call.arguments.find_keyword("memory")?;
        if !known_memory_expression(&memory.value) {
            return None;
        }
        let step_name = pipeline_step_for(call, transformer, use_span, file_ctx)?;
        let pipeline = assigned_name_for_call(call, file_ctx)?;
        Some((call.range().start(), pipeline, step_name))
    });
    let Some((_, pipeline, step_name)) = candidates.next_back() else {
        return Vec::new();
    };
    let replacement = format!("{pipeline}.named_steps[\"{step_name}\"]");
    vec![alt(
        "s6971-use-named-steps",
        "Replace the direct access to the transformer with an access to the `named_steps` attribute of the pipeline.",
        vec![text_edit(index, source, use_span, replacement)],
    )]
}

fn known_memory_expression(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::Call(_)
            | Expr::Dict(_)
            | Expr::List(_)
            | Expr::Tuple(_)
    )
}

fn pipeline_step_for(
    call: &ExprCall,
    transformer: &str,
    use_span: TextRange,
    file_ctx: &FileContext<'_>,
) -> Option<String> {
    if call.range().end() >= use_span.start() {
        return None;
    }
    if has_rebinding_between(transformer, call.range().end(), use_span.start(), file_ctx) {
        return None;
    }
    let steps = call
        .arguments
        .find_keyword("steps")
        .map(|keyword| &keyword.value)
        .or_else(|| call.arguments.args.first())?;
    let Expr::List(list) = steps else { return None };
    list.elts.iter().find_map(|element| {
        let Expr::Tuple(tuple) = element else {
            return None;
        };
        if tuple.elts.len() != 2 {
            return None;
        }
        let Expr::StringLiteral(name) = &tuple.elts[0] else {
            return None;
        };
        let Expr::Name(value) = &tuple.elts[1] else {
            return None;
        };
        (value.id.as_str() == transformer).then(|| string_value_text(&name.value))
    })
}

fn s7489(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
    issue: &Issue,
) -> Vec<Alternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(call) = find_call(file_ctx, issue_span) else {
        return Vec::new();
    };
    let Some(path) = dotted_name(&call.func) else {
        return Vec::new();
    };
    let Some(method) = path.rsplit('.').next() else {
        return Vec::new();
    };
    if !S7489_OS_CALLS.contains(&method)
        || resolve_imported_path(file_ctx, &path, call.range().start())
            .is_none_or(|resolved| resolved != format!("os.{method}"))
        || is_awaited_call(call, file_ctx)
    {
        return Vec::new();
    }
    let mut alternatives = Vec::new();
    for (library, message, id) in [
        (
            "trio",
            "Wrap with \"await trio.thread.executor\".",
            "s7489-wrap-trio-thread-executor",
        ),
        (
            "anyio",
            "Wrap with \"await anyio.thread.executor\".",
            "s7489-wrap-anyio-thread-executor",
        ),
    ] {
        let Some(alias) = plain_module_alias(file_ctx, library, call.range().start()) else {
            continue;
        };
        let callee_name = path.clone();
        let edits = vec![
            text_edit(
                index,
                source,
                call.func.range(),
                format!("await {alias}.to_thread.run_sync"),
            ),
            text_edit(
                index,
                source,
                TextRange::empty(call.arguments.range.start() + TextSize::new(1)),
                if call.arguments.is_empty() {
                    callee_name
                } else {
                    format!("{callee_name}, ")
                },
            ),
        ];
        alternatives.push(alt(id, message, edits));
    }
    alternatives
}

fn find_call<'a>(file_ctx: &'a FileContext<'_>, span: TextRange) -> Option<&'a ExprCall> {
    file_ctx
        .calls
        .iter()
        .copied()
        .find(|call| call.range() == span || call.func.range() == span)
}

fn root_name(expr: &Expr) -> Option<&ruff_python_ast::ExprName> {
    match expr {
        Expr::Name(name) => Some(name),
        Expr::Attribute(attribute) => root_name(&attribute.value),
        _ => None,
    }
}

fn is_awaited_call(call: &ExprCall, file_ctx: &FileContext<'_>) -> bool {
    file_ctx.exprs.iter().any(|expr| {
        matches!(
            expr,
            Expr::Await(await_expr) if await_expr.value.range() == call.range()
        )
    })
}

fn has_variadic_argument(call: &ExprCall) -> bool {
    call.arguments.args.iter().any(Expr::is_starred_expr)
        || call
            .arguments
            .keywords
            .iter()
            .any(|keyword| keyword.arg.is_none())
}

fn insert_before_closing_par(
    index: &LineIndex,
    source: &str,
    call: &ExprCall,
    replacement: &str,
) -> hoonarqube_ir::TextEdit {
    let close = call.arguments.range.end().to_u32().saturating_sub(1);
    text_edit(
        index,
        source,
        TextRange::empty(TextSize::from(close)),
        replacement,
    )
}

fn shift_left_edits(
    index: &LineIndex,
    source: &str,
    range: TextRange,
    amount: usize,
) -> Vec<hoonarqube_ir::TextEdit> {
    let mut edits = Vec::new();
    let mut cursor = source.line_start(range.start());
    while cursor < range.end() {
        let line_end = source.line_end(cursor);
        let end = line_end.min(range.end());
        let text = &source[cursor.to_usize()..end.to_usize()];
        let first_code = text.len() - text.trim_start_matches([' ', '\t']).len();
        if first_code >= amount {
            edits.push(text_edit(
                index,
                source,
                TextRange::new(cursor, cursor + TextSize::from(to_u32(amount))),
                "",
            ));
        }
        if line_end >= range.end() {
            break;
        }
        cursor = source.full_line_end(cursor);
    }
    edits
}

fn assigned_name_for_call(call: &ExprCall, file_ctx: &FileContext<'_>) -> Option<String> {
    file_ctx.stmts.iter().find_map(|stmt| {
        let targets = match stmt {
            Stmt::Assign(assign) if assign.value.range() == call.range() => {
                let mut targets = Vec::new();
                for target in &assign.targets {
                    collect_target_names(target, &mut targets);
                }
                targets
            }
            Stmt::AnnAssign(assign)
                if assign
                    .value
                    .as_deref()
                    .is_some_and(|value| value.range() == call.range()) =>
            {
                let mut targets = Vec::new();
                collect_target_names(&assign.target, &mut targets);
                targets
            }
            _ => return None,
        };
        (targets.len() == 1).then(|| targets.into_iter().next().unwrap())
    })
}

fn has_rebinding_between(
    name: &str,
    start: TextSize,
    end: TextSize,
    file_ctx: &FileContext<'_>,
) -> bool {
    file_ctx.stmts.iter().any(|stmt| {
        let range = stmt.range();
        if range.start() <= start || range.start() >= end {
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
        names.iter().any(|candidate| candidate == name)
    })
}

fn plain_module_alias(file_ctx: &FileContext<'_>, module: &str, at: TextSize) -> Option<String> {
    file_ctx.imports.iter().rev().find_map(|entry| {
        let AnyImport::Plain(import) = entry else {
            return None;
        };
        import.names.iter().rev().find_map(|alias| {
            let bound = alias.asname.as_ref().map_or(module, |name| name.as_str());
            if alias.name.as_str() != module
                || alias.range.start() >= at
                || import_binding_shadowed(file_ctx, bound, alias.range.end(), at)
            {
                return None;
            }
            Some(bound.to_string())
        })
    })
}

fn resolve_imported_path(file_ctx: &FileContext<'_>, path: &str, at: TextSize) -> Option<String> {
    file_ctx
        .imports
        .iter()
        .filter_map(|entry| resolve_import_entry(file_ctx, path, at, entry))
        .reduce(choose_latest_candidate)
        .map(|(_, resolved)| resolved)
}

fn choose_latest_candidate(
    best: (TextSize, String),
    candidate: (TextSize, String),
) -> (TextSize, String) {
    if candidate.0 > best.0 {
        candidate
    } else {
        best
    }
}

fn resolve_import_entry(
    file_ctx: &FileContext<'_>,
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
    file_ctx: &FileContext<'_>,
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
        .reduce(choose_latest_candidate)
}

fn resolve_from_import(
    file_ctx: &FileContext<'_>,
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
        .reduce(choose_latest_candidate)
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
    file_ctx: &FileContext<'_>,
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
            && (named_parameters(&function.parameters)
                .iter()
                .any(|parameter| parameter.parameter.name.as_str() == bound)
                || function
                    .parameters
                    .vararg
                    .as_ref()
                    .is_some_and(|parameter| parameter.name.as_str() == bound)
                || function
                    .parameters
                    .kwarg
                    .as_ref()
                    .is_some_and(|parameter| parameter.name.as_str() == bound))
    })
}
