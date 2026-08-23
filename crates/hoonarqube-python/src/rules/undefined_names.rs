use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::is_builtin_name;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S5953 — undefined names ------------------------------------------

pub(crate) fn check_undefined_names(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    if facts.dynamic_names || facts.has_wildcard_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for load in &table.resolved_loads {
        if load.in_annotation || load.target.is_some() || is_builtin_name(&load.name) {
            continue;
        }
        if is_dunder_name(&load.name) {
            continue;
        }
        issues.push(issue_at(
            "python:S5953",
            &format!("'{}' is not defined.", load.name),
            load.range,
            index,
            source,
        ));
    }
    issues
}
