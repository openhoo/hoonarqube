use crate::AnalyzerOptions;
use crate::engine::scope::BindingKind;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_has_dynamic_declaration;
use crate::support::issue_at;
use crate::support::unused_name_matches_pattern;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

// --- python:S1481 — unused local variables -----------------------------------

pub(crate) fn check_unused_locals(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    options: &AnalyzerOptions,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (scope_idx, scope) in table.scopes.iter().enumerate() {
        // Module-level bindings are the import surface: every name the
        // module binds stays importable from other files, so S1481 only
        // judges function locals (the pinned Flask globals.py contract).
        if !matches!(scope.kind, ScopeKind::Function) {
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

            let ranges: Vec<TextRange> = bindings.iter().map(|binding| binding.range).collect();
            // A local is used when a load resolves to this scope. Same-name
            // tokens elsewhere in the file (other functions, annotations,
            // unrelated scopes) must not veto the finding, so no file-wide
            // token fallback runs here.
            let used = table
                .resolved_loads
                .iter()
                .any(|load| load.target == Some(scope_idx) && load.name == *name);
            if !used {
                let issue = issue_at(
                    "python:S1481",
                    &format!("Remove the unused local variable \"{name}\"."),
                    ranges[0],
                    index,
                    source,
                );
                let alternatives = crate::quickfix::bindings::alternatives_s1481(
                    parsed, index, source, table, &issue,
                );
                let issue = alternatives.into_iter().fold(issue, |issue, alternative| {
                    issue.with_alternative(
                        alternative.id,
                        alternative.fix.message,
                        alternative.fix.edits,
                    )
                });
                issues.push(issue);
            }
        }
    }
    issues
}
