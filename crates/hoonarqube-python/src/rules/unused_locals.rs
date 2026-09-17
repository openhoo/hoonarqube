use crate::AnalyzerOptions;
use crate::engine::scope::BindingKind;
use crate::engine::scope::ScopeKind;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_has_dynamic_declaration;
use crate::support::issue_at;
use crate::support::unused_name_matches_pattern;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S1481 — unused local variables -----------------------------------

pub(crate) fn check_unused_locals(
    parsed: &Parsed<ModModule>,
    table: &SymbolTable,
    options: &AnalyzerOptions,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // Names bound inside multi-target `for` headers (`for i, x in ...`)
    // are exempt in the reference.
    let mut tuple_target_ranges = std::collections::HashSet::new();
    crate::support::for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let target = match stmt {
            Stmt::For(node) => Some(node.target.as_ref()),
            _ => None,
        };
        if let Some(ruff_python_ast::Expr::Tuple(_) | ruff_python_ast::Expr::List(_)) = target
        {
            let mut names = Vec::new();
            crate::support::collect_target_names(target.unwrap(), &mut names);
            for name in names {
                let _ = name;
            }
            collect_target_ranges(target.unwrap(), &mut tuple_target_ranges);
        }
    });
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
            if ranges
                .iter()
                .any(|range| tuple_target_ranges.contains(range))
            {
                continue;
            }
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

/// Binding ranges of every `Name` inside a destructuring target.
fn collect_target_ranges(expr: &Expr, out: &mut std::collections::HashSet<TextRange>) {
    match expr {
        Expr::Name(name) => {
            out.insert(name.range());
        }
        Expr::Tuple(tuple) => tuple.elts.iter().for_each(|e| collect_target_ranges(e, out)),
        Expr::List(list) => list.elts.iter().for_each(|e| collect_target_ranges(e, out)),
        Expr::Starred(starred) => collect_target_ranges(&starred.value, out),
        _ => {}
    }
}
