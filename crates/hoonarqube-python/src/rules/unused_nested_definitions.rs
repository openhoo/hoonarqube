use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::definition_is_used;
use crate::support::is_dunder_name;
use crate::support::is_private_name;
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
        let (key, message) = match site.flavor {
            DefFlavor::Function if is_private_name(&site.name) => (
                "python:S5603",
                format!(
                    "Remove this unused private nested function '{}'.",
                    site.name
                ),
            ),
            DefFlavor::Function => (
                "python:S5603",
                format!("Remove this unused nested function '{}'.", site.name),
            ),
            DefFlavor::Class => (
                "python:S5603",
                format!("Remove this unused nested class '{}'.", site.name),
            ),
        };
        issues.push(issue_at(key, &message, site.name_range, index, source));
    }
    issues
}
