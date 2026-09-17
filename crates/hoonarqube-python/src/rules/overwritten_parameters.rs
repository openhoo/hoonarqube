use crate::engine::scope::BindingKind;
use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// ---------------------------------------------------------------------------
// value: liveness & value tracking.
// ---------------------------------------------------------------------------

// --- python:S1226 — ignored parameter initial values --------------------------

pub(crate) fn check_overwritten_parameters(
    parsed: &ruff_python_parser::Parsed<ruff_python_ast::ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // Statement ranges let a load on the right-hand side of the first
    // overwriting assignment (`x = x + 1`) count as reading the initial
    // parameter value, matching the reference's live-variables analysis.
    let mut statement_ranges: Vec<TextRange> = Vec::new();
    crate::support::for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if matches!(
            stmt,
            ruff_python_ast::Stmt::Assign(_)
                | ruff_python_ast::Stmt::AugAssign(_)
                | ruff_python_ast::Stmt::AnnAssign(_)
        ) {
            statement_ranges.push(stmt.range());
        }
    });
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function {
            continue;
        }
        let scope = &table.scopes[site.own_scope];
        for (param_name, param_range) in &site.params {
            if param_name.starts_with('_') || matches!(param_name.as_str(), "self" | "cls") {
                continue;
            }
            let Some(bindings) = scope.bindings.get(param_name) else {
                continue;
            };
            let overwrites: Vec<TextRange> = bindings
                .iter()
                .filter(|binding| binding.kind == BindingKind::Assignment)
                .map(|binding| binding.range)
                .collect();
            let loads: Vec<TextRange> = table
                .resolved_loads
                .iter()
                .filter(|load| load.target == Some(site.own_scope) && load.name == *param_name)
                .map(|load| load.range)
                .collect();
            let Some(&first_overwrite) = overwrites.iter().reduce(|left, right| {
                if right.start() < left.start() {
                    right
                } else {
                    left
                }
            }) else {
                continue;
            };
            // The initial value counts as read when the parameter is loaded
            // before the overwrite, or when any other textual occurrence
            // (f-string interior, keyword name, nested closure) sits between
            // the parameter and the overwriting assignment.
            // Loads inside the first overwriting statement but outside the
            // target range are right-hand-side reads of the initial value.
            let overwrite_statement = statement_ranges.iter().find(|range| {
                range.start() <= first_overwrite.start()
                    && first_overwrite.end() <= range.end()
            });
            let read_on_overwrite_rhs = overwrite_statement.is_some_and(|statement| {
                loads.iter().any(|range| {
                    statement.start() <= range.start()
                        && range.end() <= statement.end()
                        && range.start() != first_overwrite.start()
                })
            });
            let read_before_overwrite = loads
                .iter()
                .any(|range| range.start() < first_overwrite.start())
                || read_on_overwrite_rhs
                || facts.token_names.iter().any(|(token_name, range)| {
                    let belongs_to_parameter = token_name == param_name;
                    let follows_parameter = range.start() >= param_range.end();
                    let precedes_overwrite = range.end() <= first_overwrite.start();
                    belongs_to_parameter && follows_parameter && precedes_overwrite
                });
            let read_after_overwrite = loads
                .iter()
                .any(|range| range.end() > first_overwrite.end())
                || facts.token_names.iter().any(|(token_name, range)| {
                    let belongs_to_parameter = token_name == param_name;
                    let follows_overwrite = range.start() >= first_overwrite.end();
                    let is_not_an_overwrite = !overwrites.contains(range);
                    belongs_to_parameter && follows_overwrite && is_not_an_overwrite
                });
            let used_in_sub_function = table.resolved_loads.iter().any(|load| {
                load.target == Some(site.own_scope)
                    && load.name == *param_name
                    && load.scope != site.own_scope
            });
            if !read_before_overwrite && read_after_overwrite && !used_in_sub_function {
                issues.push(issue_at(
                    "python:S1226",
                    &format!(
                        "Introduce a new variable or use its initial value before reassigning '{param_name}'."
                    ),
                    *param_range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
