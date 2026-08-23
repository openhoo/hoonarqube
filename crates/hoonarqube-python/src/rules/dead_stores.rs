use crate::AnalyzerOptions;
use crate::engine::scope::Binding;
use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_has_dynamic_declaration;
use crate::support::issue_at;
use crate::support::unused_name_matches_pattern;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

// --- python:S1854 — dead stores ----------------------------------------------

pub(crate) fn check_dead_stores(
    table: &SymbolTable,
    facts: &FileFacts,
    options: &AnalyzerOptions,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    if facts.dynamic_names {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for (scope_idx, scope) in table.scopes.iter().enumerate() {
        if !matches!(scope.kind, ScopeKind::Module | ScopeKind::Function) {
            continue;
        }
        for (name, bindings) in &scope.bindings {
            if name.starts_with('_')
                || unused_name_matches_pattern(name, &options.unused_local_ignore_pattern)
                || scope_has_dynamic_declaration(scope, name)
                || bindings
                    .iter()
                    .any(|binding| binding.kind != BindingKind::Assignment)
            {
                continue;
            }
            let mut stores: Vec<&Binding> = bindings.iter().collect();
            stores.sort_by_key(|binding| binding.range.start());
            let Some(last) = stores.last() else { continue };
            let store_ranges: Vec<TextRange> = stores.iter().map(|b| b.range).collect();
            let earlier_loads = table
                .resolved_loads
                .iter()
                .filter(|load| load.target == Some(scope_idx) && load.name == *name)
                .filter(|load| load.range.start() < last.range.start())
                .count();
            let loaded_after = table.resolved_loads.iter().any(|load| {
                load.target == Some(scope_idx)
                    && load.name == *name
                    && load.range.start() > last.range.start()
            }) || facts.token_names.iter().any(|(token_name, range)| {
                token_name == name
                    && range.start() > last.range.end()
                    && !store_ranges.contains(range)
            });
            if earlier_loads > 0 && !loaded_after && last.loop_depth == 0 {
                issues.push(issue_at(
                    "python:S1854",
                    &format!("Remove this useless assignment to local variable '{name}'."),
                    last.range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
