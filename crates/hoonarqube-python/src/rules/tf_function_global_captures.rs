use crate::engine::scope::BindingKind;
use crate::engine::scope::DefFlavor;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_is_within;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use std::collections::HashSet;

pub(crate) fn check_tf_function_global_captures(
    table: &SymbolTable,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function || !site.tf_traced {
            continue;
        }
        let mut reported: HashSet<String> = HashSet::new();
        for load in &table.resolved_loads {
            if load.target != Some(0)
                || load.name.starts_with('_')
                || !scope_is_within(table, load.scope, site.own_scope)
            {
                continue;
            }
            if !reported.insert(load.name.clone()) {
                continue;
            }
            let is_variable = table.scopes[0]
                .bindings
                .get(&load.name)
                .is_some_and(|bindings| {
                    bindings
                        .iter()
                        .any(|binding| binding.kind == BindingKind::Assignment)
                });
            if is_variable {
                issues.push(issue_at(
                    "python:S6911",
                    &format!("'{}' is captured from module scope inside this tf.function; pass it as an argument.", load.name),
                    load.range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- python:S6911 / S6918 / S6928 — tf.function contracts ----------------------
