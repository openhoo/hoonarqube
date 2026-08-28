use crate::engine::scope::DefFlavor;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S1172 — unused function parameters -------------------------------

pub(crate) fn check_unused_parameters(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function || site.decorated {
            continue;
        }
        for (param_name, param_range) in &site.params {
            if param_name.starts_with('_') || matches!(param_name.as_str(), "self" | "cls") {
                continue;
            }
            let used = table
                .resolved_loads
                .iter()
                .any(|load| load.target == Some(site.own_scope) && load.name == *param_name)
                || name_used_in_tokens(facts, param_name, &[*param_range]);
            if !used {
                issues.push(issue_at(
                    "python:S1172",
                    &format!("Remove the unused function parameter \"{param_name}\"."),
                    *param_range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
