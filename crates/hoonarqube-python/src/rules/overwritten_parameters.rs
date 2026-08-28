use crate::engine::scope::BindingKind;
use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

// ---------------------------------------------------------------------------
// value: liveness & value tracking.
// ---------------------------------------------------------------------------

// --- python:S1226 — ignored parameter initial values --------------------------

pub(crate) fn check_overwritten_parameters(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
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
            let loads: Vec<TextRange> =
                table.resolved_loads.iter().map(|load| load.range).collect();
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
            let read_before_overwrite = loads
                .iter()
                .any(|range| range.start() < first_overwrite.start())
                || facts.token_names.iter().any(|(token_name, range)| {
                    token_name == param_name
                        && range.start() >= param_range.end()
                        && range.end() <= first_overwrite.start()
                });
            let read_after_overwrite = loads
                .iter()
                .any(|range| range.end() > first_overwrite.end())
                || facts.token_names.iter().any(|(token_name, range)| {
                    token_name == param_name
                        && range.start() >= first_overwrite.end()
                        && !overwrites.contains(range)
                });
            if !read_before_overwrite && read_after_overwrite {
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
