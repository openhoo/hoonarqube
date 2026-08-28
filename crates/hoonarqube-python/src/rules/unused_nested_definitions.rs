use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::definition_is_used;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_unused_nested_definitions(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if !matches!(table.scopes[site.enclosing_scope].kind, ScopeKind::Function)
            || site.decorated
            || is_dunder_name(&site.name)
            || definition_is_used(table, facts, site)
        {
            continue;
        }
        let message = match site.flavor {
            DefFlavor::Function => "Remove this unused function declaration.",
            DefFlavor::Class => "Remove this unused class declaration.",
        };
        issues.push(issue_at(
            "python:S5603",
            message,
            site.name_range,
            index,
            source,
        ));
    }
    issues
}
