use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::issue_at;
use crate::support::module_all_exports;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S5807 — __all__ names must exist ---------------------------------

pub(crate) fn check_all_exports_exist(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // Sonar's UndefinedNameAllPropertyCheck exempts modules defining
    // module-level __getattr__ or __dir__ — they resolve __all__ entries
    // dynamically.
    let has_dynamic_lookup = parsed.syntax().body.iter().any(|stmt| {
        matches!(stmt, Stmt::FunctionDef(f) if matches!(f.name.as_str(), "__getattr__" | "__dir__"))
    });
    if facts.dynamic_names || facts.has_wildcard_import || has_dynamic_lookup {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for (exported, range) in module_all_exports(parsed) {
        if !table.scopes[0].bindings.contains_key(&exported) {
            issues.push(issue_at(
                "python:S5807",
                &format!("Change or remove this string; \"{exported}\" is not defined."),
                range,
                index,
                source,
            ));
        }
    }
    issues
}
