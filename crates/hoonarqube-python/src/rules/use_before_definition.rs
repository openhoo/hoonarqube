use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S3827 — use before definition ------------------------------------

pub(crate) fn check_use_before_definition(
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
        if load.scope != 0 || load.in_annotation || load.target != Some(0) {
            continue;
        }
        let Some(bindings) = table.scopes[0].bindings.get(&load.name) else {
            continue;
        };
        let Some(first_definition) = bindings.iter().map(|b| b.range.start()).min() else {
            continue;
        };
        if load.range.end() <= first_definition {
            issues.push(issue_at(
                "python:S3827",
                &format!("'{}' is used before it is defined.", load.name),
                load.range,
                index,
                source,
            ));
        }
    }
    issues
}
