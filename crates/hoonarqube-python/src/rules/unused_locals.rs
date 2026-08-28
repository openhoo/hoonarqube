use crate::AnalyzerOptions;
use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::engine::scope::scope_has_dynamic_declaration;
use crate::support::issue_at;
use crate::support::unused_name_matches_pattern;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

// --- python:S1481 — unused local variables -----------------------------------

pub(crate) fn check_unused_locals(
    table: &SymbolTable,
    facts: &FileFacts,
    options: &AnalyzerOptions,
    exports: &[(String, TextRange)],
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (scope_idx, scope) in table.scopes.iter().enumerate() {
        if !matches!(scope.kind, ScopeKind::Module | ScopeKind::Function) {
            continue;
        }
        for (name, bindings) in &scope.bindings {
            if name.starts_with('_')
                || unused_name_matches_pattern(name, &options.unused_local_ignore_pattern)
                || scope_has_dynamic_declaration(scope, name)
                || bindings.iter().any(|binding| {
                    !matches!(
                        binding.kind,
                        BindingKind::Assignment | BindingKind::ExceptName
                    )
                })
            {
                continue;
            }
            if scope_idx == 0 && exports.iter().any(|(exported, _)| exported == name) {
                continue;
            }
            let ranges: Vec<TextRange> = bindings.iter().map(|binding| binding.range).collect();
            let used = table
                .resolved_loads
                .iter()
                .any(|load| load.target == Some(scope_idx) && load.name == *name)
                || name_used_in_tokens(facts, name, &ranges);
            if !used {
                issues.push(issue_at(
                    "python:S1481",
                    &format!("Remove the unused local variable \"{name}\"."),
                    ranges[0],
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
