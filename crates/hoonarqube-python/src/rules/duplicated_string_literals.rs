use crate::AnalyzerOptions;
use crate::support::child_bodies;
use crate::support::excluded_by_pattern;
use crate::support::for_each_expr;
use crate::support::is_standalone_string_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::string_value_text;
use crate::support::to_range;
use hoonarqube_ir::FlowLocation;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashMap;
use std::collections::HashSet;

pub(crate) fn check_duplicated_string_literals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let threshold = (options.duplicate_literal_threshold.max(2)) as usize;
    let mut occurrences: Vec<(String, TextRange)> = Vec::new();
    collect_file_wide(parsed.syntax().body.as_slice(), &mut occurrences);

    // The reference contract tallies eligible literals file-wide: module,
    // class, and function scopes share one grouping; the first occurrence
    // carries the primary finding and later occurrences become secondary
    // locations.
    let mut totals: HashMap<&str, usize> = HashMap::new();
    for (text, _) in &occurrences {
        *totals.entry(text.as_str()).or_insert(0) += 1;
    }
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut issues = Vec::new();
    for (text, range) in &occurrences {
        if !emitted.insert(text.as_str()) {
            continue;
        }
        let total = totals[text.as_str()];
        if total < threshold
            || excluded_by_pattern(&options.duplicate_literal_exclusion_regex, text)
        {
            continue;
        }
        let mut issue = issue_at(
            "python:S1192",
            &format!(
                "Define a constant instead of duplicating this literal {} {total} times.",
                &source[*range]
            ),
            *range,
            index,
            source,
        );
        let secondary_locations = occurrences
            .iter()
            .filter(|(candidate, _)| candidate == text)
            .skip(1)
            .map(|(_, secondary_range)| {
                FlowLocation::in_primary_file(
                    "Duplication",
                    to_range(*secondary_range, index, source),
                )
            })
            .collect::<Vec<_>>();
        if !secondary_locations.is_empty() {
            issue = issue.with_flow(secondary_locations);
        }
        issues.push(issue);
    }
    issues
}

/// Every plain string literal except suite-leading docstrings, in one
/// file-wide source-ordered occurrence list. Function headers (decorators,
/// defaults, annotations) evaluate in the enclosing scope.
fn collect_file_wide(suite: &[Stmt], out: &mut Vec<(String, TextRange)>) {
    for (position, stmt) in suite.iter().enumerate() {
        if position != 0 || !is_standalone_string_stmt(stmt) {
            collect_stmt_literals(stmt, out);
        }
        for body in child_bodies(stmt) {
            collect_file_wide(body, out);
        }
    }
}

fn collect_stmt_literals(stmt: &Stmt, out: &mut Vec<(String, TextRange)>) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::StringLiteral(literal) = expr {
                out.push((string_value_text(&literal.value), literal.range()));
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #111–#193 (python:S1192 … python:S7489).
//
// One private check per catalog entry, aggregated through
// `check_tier_a_battery_2`. Detection follows the batch spec: single-file
// AST/token/text heuristics with deliberately conservative predicates.
