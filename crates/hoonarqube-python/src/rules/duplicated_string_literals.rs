use crate::AnalyzerOptions;
use crate::support::child_bodies;
use crate::support::excluded_by_pattern;
use crate::support::for_each_expr;
use crate::support::is_standalone_string_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashMap;

pub(crate) fn check_duplicated_string_literals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let threshold = (options.duplicate_literal_threshold.max(2)) as usize;
    let mut occurrences: Vec<(Option<u32>, String, TextRange)> = Vec::new();
    let mut scopes = 0_u32;
    collect_function_scoped(
        parsed.syntax().body.as_slice(),
        None,
        &mut scopes,
        &mut occurrences,
    );

    // CE counts duplicated literals within one function scope; module-level
    // occurrences never accumulate.
    let mut totals: HashMap<Option<u32>, HashMap<String, usize>> = HashMap::new();
    for (scope, text, _) in &occurrences {
        if let Some(scope) = scope {
            *totals
                .entry(Some(*scope))
                .or_default()
                .entry(text.clone())
                .or_insert(0) += 1;
        }
    }
    let mut seen: HashMap<(Option<u32>, String), usize> = HashMap::new();
    let mut issues = Vec::new();
    for (scope, text, range) in &occurrences {
        let total = totals
            .get(scope)
            .and_then(|texts| texts.get(text))
            .copied()
            .unwrap_or(0);
        let nth = seen.entry((*scope, text.clone())).or_insert(0);
        *nth += 1;
        let excluded = excluded_by_pattern(&options.duplicate_literal_exclusion_regex, text);
        if total >= threshold && *nth > 1 && !excluded {
            issues.push(issue_at(
                "python:S1192",
                &format!("This string literal appears {total} times; extract it into a constant."),
                *range,
                index,
                source,
            ));
        }
    }
    issues
}

/// Every plain string literal except suite-leading docstrings, attributed to
/// its nearest enclosing function (`None` = module level). Function headers
/// (decorators, defaults, annotations) evaluate in the enclosing scope.
fn collect_function_scoped(
    suite: &[Stmt],
    scope: Option<u32>,
    next_scope: &mut u32,
    out: &mut Vec<(Option<u32>, String, TextRange)>,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if position != 0 || !is_standalone_string_stmt(stmt) {
            collect_stmt_literals(stmt, scope, out);
        }
        collect_child_literals(stmt, scope, next_scope, out);
    }
}

fn collect_stmt_literals(
    stmt: &Stmt,
    scope: Option<u32>,
    out: &mut Vec<(Option<u32>, String, TextRange)>,
) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::StringLiteral(literal) = expr {
                out.push((scope, string_value_text(&literal.value), literal.range()));
            }
        });
    }
}

fn collect_child_literals(
    stmt: &Stmt,
    scope: Option<u32>,
    next_scope: &mut u32,
    out: &mut Vec<(Option<u32>, String, TextRange)>,
) {
    let child_scope = if matches!(stmt, Stmt::FunctionDef(_)) {
        *next_scope += 1;
        Some(*next_scope)
    } else {
        scope
    };
    for body in child_bodies(stmt) {
        collect_function_scoped(body, child_scope, next_scope, out);
    }
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #111–#193 (python:S1192 … python:S7489).
//
// One private check per catalog entry, aggregated through
// `check_tier_a_battery_2`. Detection follows the batch spec: single-file
// AST/token/text heuristics with deliberately conservative predicates.
