use crate::engine::scope::DefFlavor;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_is_within;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S2325 — methods that could be static -------------------------------

pub(crate) fn check_static_candidates(
    table: &SymbolTable,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function
            || site.decorated
            || !matches!(table.scopes[site.enclosing_scope].kind, ScopeKind::Class)
            || is_dunder_name(&site.name)
        {
            continue;
        }
        let Some((first_parameter, _)) = site.params.first() else {
            continue;
        };
        if first_parameter.as_str() != "self" {
            continue;
        }
        let self_used = table.resolved_loads.iter().any(|load| {
            matches!(load.name.as_str(), "self" | "super")
                && scope_is_within(table, load.scope, site.own_scope)
        });
        if !self_used {
            issues.push(issue_at(
                "python:S2325",
                "Make this method static.",
                site.name_range,
                index,
                source,
            ));
        }
    }
    issues
}
