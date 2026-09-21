use crate::engine::scope::BindingKind;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::comment_tokens;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashMap;
use std::path::Path;

// --- python:S1128 — unused imports ------------------------------------------
//
// The reference never reports `__init__.py` (facade re-export modules),
// exempts `__future__`/`typing`/`typing_extensions` imports and
// `sklearn.experimental.*` names, and treats a name mentioned in any comment
// or bound as a whole string literal (`__all__` entries, type-hint comments)
// as used.

const ALLOWED_MODULES: [&str; 3] = ["__future__", "typing", "typing_extensions"];
const ALLOWED_FQN_PREFIX: &str = "sklearn.experimental.";

pub(crate) fn check_unused_imports(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
    path: &Path,
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> Vec<Issue> {
    if path.file_name().is_some_and(|name| name == "__init__.py") {
        return Vec::new();
    }
    let import_modules = import_module_names(file_ctx);
    let comments: Vec<&str> = comment_tokens(parsed)
        .map(|token| &source[token.range()])
        .collect();
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
        if import_ranges.iter().any(|range| {
            import_modules
                .get(range)
                .is_some_and(|module| import_is_allowed(module))
        }) {
            continue;
        }
        let used = table
            .resolved_index
            .get(name.as_str())
            .is_some_and(|indices| {
                indices
                    .iter()
                    .any(|&index| table.resolved_loads[index as usize].target == Some(0))
            })
            || name_used_in_tokens(facts, name, &import_ranges)
            || comments
                .iter()
                .any(|comment| comment.contains(name.as_str()))
            || facts.string_texts.iter().any(|text| text == name);
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

/// `__future__`, `typing`, `typing_extensions`, and `sklearn.experimental.*`
/// imports are exempt regardless of usage.
fn import_is_allowed(module: &str) -> bool {
    ALLOWED_MODULES.contains(&module) || module.starts_with(ALLOWED_FQN_PREFIX)
}

/// Maps each import binding range to its dotted module name: `from a.b
/// import c` yields `a.b` for `c`'s range, `import a.b` yields `a.b`.
fn import_module_names(
    file_ctx: &crate::engine::file_context::FileContext<'_>,
) -> HashMap<TextRange, String> {
    let mut modules = HashMap::new();
    for stmt in file_ctx.stmts.iter().copied() {
        match stmt {
            Stmt::ImportFrom(import) => {
                let module = import
                    .module
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                for alias in &import.names {
                    let range = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.range(), Ranged::range);
                    modules.insert(range, module.clone());
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let range = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.range(), Ranged::range);
                    modules.insert(range, alias.name.to_string());
                }
            }
            _ => {}
        }
    }
    modules
}
