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
    // Literals inside decorators and type annotations are excluded.
    let mut excluded_ranges: Vec<TextRange> = Vec::new();
    collect_excluded_ranges(parsed.syntax().body.as_slice(), &mut excluded_ranges);
    let mut occurrences: Vec<(String, String, TextRange)> = Vec::new();
    collect_file_wide(
        parsed.syntax().body.as_slice(),
        &excluded_ranges,
        source,
        &mut occurrences,
    );

    // The reference contract tallies eligible literals file-wide: module,
    // class, and function scopes share one grouping; the first occurrence
    // carries the primary finding and later occurrences become secondary
    // locations.
    let mut totals: HashMap<&str, usize> = HashMap::new();
    for (text, _, _) in &occurrences {
        *totals.entry(text.as_str()).or_insert(0) += 1;
    }
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut issues = Vec::new();
    for (text, value, range) in &occurrences {
        if !emitted.insert(text.as_str()) {
            continue;
        }
        let total = totals[text.as_str()];
        if total < threshold || literal_is_excluded(value, options) {
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
            .filter(|(candidate, _, _)| candidate == text)
            .skip(1)
            .map(|(_, _, secondary_range)| {
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

/// Ranges of decorator and type-annotation expressions: literals inside
/// them never count.
fn collect_excluded_ranges(suite: &[Stmt], out: &mut Vec<TextRange>) {
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => collect_function_exclusions(function, out),
            Stmt::ClassDef(class) => {
                out.extend(class.decorator_list.iter().map(Ranged::range));
            }
            Stmt::AnnAssign(assign) => out.push(assign.annotation.range()),
            _ => {}
        }
        for body in child_bodies(stmt) {
            collect_excluded_ranges(body, out);
        }
    }
}

/// Every plain string literal except standalone string statements
/// (docstrings and bare literal statements), in one file-wide
/// source-ordered occurrence list. The grouping key is the raw literal
/// text including quotes and prefixes, matching the reference.
///
/// Decorators, parameter annotations, and the return annotation of a
/// function are excluded literal ranges.
fn collect_function_exclusions(
    function: &ruff_python_ast::StmtFunctionDef,
    out: &mut Vec<TextRange>,
) {
    out.extend(function.decorator_list.iter().map(Ranged::range));
    for parameter in function
        .parameters
        .posonlyargs
        .iter()
        .chain(&function.parameters.args)
        .chain(&function.parameters.kwonlyargs)
    {
        if let Some(annotation) = &parameter.parameter.annotation {
            out.push(annotation.range());
        }
    }
    if let Some(returns) = &function.returns {
        out.push(returns.range());
    }
}

fn collect_file_wide(
    suite: &[Stmt],
    excluded: &[TextRange],
    source: &str,
    out: &mut Vec<(String, String, TextRange)>,
) {
    for stmt in suite {
        if !is_standalone_string_stmt(stmt) {
            collect_stmt_literals(stmt, excluded, source, out);
        }
        for body in child_bodies(stmt) {
            collect_file_wide(body, excluded, source, out);
        }
    }
}

fn collect_stmt_literals(
    stmt: &Stmt,
    excluded: &[TextRange],
    source: &str,
    out: &mut Vec<(String, String, TextRange)>,
) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |expr| {
            if let Expr::StringLiteral(literal) = expr
                && !excluded
                    .iter()
                    .any(|range| range.contains_range(literal.range()))
            {
                // The reference groups by the literal's raw token text
                // (quotes and prefixes included), while the exclusion
                // checks use the unescaped value.
                out.push((
                    source[literal.range()].to_string(),
                    string_value_text(&literal.value),
                    literal.range(),
                ));
            }
        });
    }
}

/// Reference exclusions: literals shorter than 5 chars, identifier-like
/// literals (`^[_\-a-zA-Z0-9]+$`), formatting patterns
/// (`^[0-9{} .\-_%:dfrsymhYMHS<>]+$`), `#rrggbb` colors, and the custom
/// exclusion pattern.
fn literal_is_excluded(value: &str, options: &AnalyzerOptions) -> bool {
    value.len() < 5
        || is_identifier_like(value)
        || is_formatting_pattern(value)
        || is_hex_color(value)
        || excluded_by_pattern(&options.duplicate_literal_exclusion_regex, value)
}

/// `^[_\-a-zA-Z0-9]+$`: identifier-like literals are exempt.
fn is_identifier_like(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `^[0-9{} .\-_%:dfrsymhYMHS<>]+$`: formatting patterns are exempt.
fn is_formatting_pattern(value: &str) -> bool {
    value.chars().all(|c| {
        matches!(
            c,
            '0'..='9'
                | '{'
                | '}'
                | ' '
                | '.'
                | '-'
                | '_'
                | '%'
                | ':'
                | 'd'
                | 'f'
                | 'r'
                | 's'
                | 'y'
                | 'm'
                | 'h'
                | 'Y'
                | 'M'
                | 'H'
                | 'S'
                | '<'
                | '>'
        )
    })
}

/// `#rrggbb` hex colors are exempt.
fn is_hex_color(value: &str) -> bool {
    value.len() == 7 && value.starts_with('#') && value[1..].chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #111–#193 (python:S1192 … python:S7489).
//
// One private check per catalog entry, aggregated through
// `check_tier_a_battery_2`. Detection follows the batch spec: single-file
// AST/token/text heuristics with deliberately conservative predicates.
