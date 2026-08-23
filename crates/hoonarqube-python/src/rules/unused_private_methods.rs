use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::is_private_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S1144 — unused private methods -----------------------------------

pub(crate) fn check_unused_private_methods(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function
            || site.decorated
            || !matches!(table.scopes[site.enclosing_scope].kind, ScopeKind::Class)
            || !is_private_name(&site.name)
        {
            continue;
        }
        let referenced = facts.attr_reads.iter().any(|(attr, _)| attr == &site.name)
            || facts.called_names.contains(&site.name)
            || facts
                .string_texts
                .iter()
                .any(|text| text.contains(&site.name))
            || name_used_in_tokens(facts, &site.name, &[site.name_range]);
        if !referenced {
            issues.push(issue_at(
                "python:S1144",
                &format!("Remove this unused private method '{}'.", site.name),
                site.name_range,
                index,
                source,
            ));
        }
    }
    issues
}
