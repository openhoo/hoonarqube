use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::support::is_builtin_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S5806 — shadowed builtins ----------------------------------------

pub(crate) fn check_shadowed_builtins(
    table: &SymbolTable,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for scope in &table.scopes {
        // CE flags builtin shadowing by function-local bindings only; module-
        // and class-level rebinding stays out of the rule's scope.
        if !matches!(scope.kind, ScopeKind::Function) {
            continue;
        }
        for (name, bindings) in &scope.bindings {
            if !is_builtin_name(name) {
                continue;
            }
            if let Some(binding) = bindings.first() {
                issues.push(issue_at(
                    "python:S5806",
                    "Rename this variable; it shadows a builtin.",
                    binding.range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
