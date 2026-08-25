use crate::engine::file_context::FileContext;
use crate::engine::scope::SymbolTable;
use crate::support::KNOWN_STEP_HINTS;
use crate::support::issue_at;
use crate::support::unmasked_segments;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

// --- python:S6972 — nested estimator parameter names ---------------------------

pub(crate) fn check_nested_estimator_parameters(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let sklearn_present = unmasked_segments(parsed, source)
        .iter()
        .any(|(_, segment)| segment.contains("sklearn"));
    if !sklearn_present {
        return Vec::new();
    }
    let mut known: HashSet<String> = KNOWN_STEP_HINTS
        .iter()
        .map(|hint| (*hint).to_string())
        .collect();
    known.extend(table.scopes[0].bindings.keys().cloned());
    for site in &table.def_sites {
        known.insert(site.name.clone());
    }
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        for keyword in &call.arguments.keywords {
            let Some(arg) = &keyword.arg else { continue };
            let Some(separator) = arg.as_str().find("__") else {
                continue;
            };
            let prefix = &arg.as_str()[..separator];
            if !known.contains(prefix) {
                issues.push(issue_at(
                    "python:S6972",
                    &format!("'{prefix}' does not match a known pipeline step; verify this nested parameter."),
                    keyword.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
