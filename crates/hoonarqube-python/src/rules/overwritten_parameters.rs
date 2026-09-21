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
    _parsed: &ruff_python_parser::Parsed<ruff_python_ast::ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> Vec<Issue> {
    // Statement ranges let a load on the right-hand side of the first
    // overwriting assignment (`x = x + 1`) count as reading the initial
    // parameter value, matching the reference's live-variables analysis.
    // Name targets of augmented assignments read the bound value before
    // writing the combined result, so their ranges double as loads.
    let mut scan = OverwriteScan::default();
    for stmt in file_ctx.stmts.iter().copied() {
        if let ruff_python_ast::Stmt::AugAssign(assign) = stmt
            && let ruff_python_ast::Expr::Name(target) = assign.target.as_ref()
        {
            scan.augmented_targets.push(target.range());
        }
        if matches!(
            stmt,
            ruff_python_ast::Stmt::Assign(_)
                | ruff_python_ast::Stmt::AugAssign(_)
                | ruff_python_ast::Stmt::AnnAssign(_)
        ) {
            scan.statement_ranges.push(stmt.range());
        }
    }
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function {
            continue;
        }
        check_function_parameters(site, table, facts, &scan, index, source, &mut issues);
    }
    issues
}

/// Assignment statements relevant to parameter liveness: every overwriting
/// statement range plus the name targets of augmented assignments.
#[derive(Default)]
struct OverwriteScan {
    statement_ranges: Vec<TextRange>,
    augmented_targets: Vec<TextRange>,
}

/// Flags each parameter of `site` whose initial value is never read before
/// its first overwriting assignment.
fn check_function_parameters(
    site: &crate::engine::scope::DefSite,
    table: &SymbolTable,
    facts: &FileFacts,
    scan: &OverwriteScan,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
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
            .resolved_index
            .get(param_name.as_str())
            .map(|indices| {
                indices
                    .iter()
                    .filter(|&&index| {
                        table.resolved_loads[index as usize].target == Some(site.own_scope)
                    })
                    .map(|&index| table.resolved_loads[index as usize].range)
                    .collect()
            })
            .unwrap_or_default();
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
        let overwrite_statement = scan.statement_ranges.iter().find(|range| {
            range.start() <= first_overwrite.start() && first_overwrite.end() <= range.end()
        });
        let read_on_overwrite_rhs = overwrite_statement.is_some_and(|statement| {
            loads.iter().any(|range| {
                statement.start() <= range.start()
                    && range.end() <= statement.end()
                    && range.start() != first_overwrite.start()
            })
        });
        // An augmented assignment target is a read-modify-write: `pcm += b`
        // loads the incoming value before storing the combined result.
        let read_before_overwrite = scan.augmented_targets.contains(&first_overwrite)
            || loads
                .iter()
                .any(|range| range.start() < first_overwrite.start())
            || read_on_overwrite_rhs
            || facts
                .token_index
                .get(param_name.as_str())
                .is_some_and(|indices| {
                    indices.iter().any(|&index| {
                        let range = facts.token_names[index as usize].1;
                        range.start() >= param_range.end() && range.end() <= first_overwrite.start()
                    })
                });
        let read_after_overwrite = loads
            .iter()
            .any(|range| range.end() > first_overwrite.end())
            || facts
                .token_index
                .get(param_name.as_str())
                .is_some_and(|indices| {
                    indices.iter().any(|&index| {
                        let range = facts.token_names[index as usize].1;
                        range.start() >= first_overwrite.end() && !overwrites.contains(&range)
                    })
                });
        let used_in_sub_function =
            table
                .resolved_index
                .get(param_name.as_str())
                .is_some_and(|indices| {
                    indices.iter().any(|&index| {
                        let load = &table.resolved_loads[index as usize];
                        load.target == Some(site.own_scope) && load.scope != site.own_scope
                    })
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
