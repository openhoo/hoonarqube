use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

// --- python:S1128 — unused imports ------------------------------------------

pub(crate) fn check_unused_imports(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, bindings) in &table.scopes[0].bindings {
        let import_ranges: Vec<TextRange> = bindings
            .iter()
            .filter(|binding| binding.kind == BindingKind::Import)
            .map(|binding| binding.range)
            .collect();
        if import_ranges.is_empty() {
            continue;
        }
        let used = table
            .resolved_loads
            .iter()
            .any(|load| load.target == Some(0) && load.name == *name)
            || name_used_in_tokens(facts, name, &import_ranges);
        if !used {
            for range in import_ranges {
                issues.push(issue_at(
                    "python:S1128",
                    "Remove this unused import.",
                    range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
