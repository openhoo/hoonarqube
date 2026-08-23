use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::definition_is_used;
use crate::support::is_private_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_unused_private_nested_classes(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Class
            || site.decorated
            || !is_private_name(&site.name)
            || matches!(table.scopes[site.enclosing_scope].kind, ScopeKind::Module)
            || definition_is_used(table, facts, site)
        {
            continue;
        }
        issues.push(issue_at(
            "python:S3985",
            &format!("Remove this unused private nested class '{}'.", site.name),
            site.name_range,
            index,
            source,
        ));
    }
    issues
}
