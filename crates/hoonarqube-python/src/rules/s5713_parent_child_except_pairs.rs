use crate::support::direct_base_names;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashMap;
use std::collections::HashSet;

/// python:S5713 — flags except-tuples listing both a parent and its subclass
/// when both names resolve to file-local classes; one finding per handler.
pub(crate) fn check_s5713_parent_child_except_pairs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let classes = module_classes(module);
    let mut issues = Vec::new();
    for_each_stmt(module, &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else {
            return;
        };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let Some(Expr::Tuple(tuple)) = inner.type_.as_deref() else {
                continue;
            };
            let names: Vec<&str> = tuple
                .elts
                .iter()
                .filter_map(|element| match element {
                    Expr::Name(name) => Some(name.id.as_str()),
                    _ => None,
                })
                .collect();
            let mut pair_found: Option<(&str, &str)> = None;
            for child in &names {
                for parent in &names {
                    if child == parent
                        || !classes.contains_key(child)
                        || !classes.contains_key(parent)
                    {
                        continue;
                    }
                    let mut visited = HashSet::new();
                    if has_file_local_ancestor(child, parent, &classes, &mut visited) {
                        pair_found = Some((child, parent));
                    }
                }
            }
            if let Some((child, parent)) = pair_found {
                issues.push(issue_at(
                    "python:S5713",
                    &format!(
                        "'{child}' is already a subclass of '{parent}'; \
                         remove one of them from this except clause."
                    ),
                    tuple.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- migrated from support/mod.rs (S5713) ---
// --- python:S5713 — subclass and parent should not share an except clause -----

/// Module-level file-local classes by name.
pub(crate) fn module_classes(module: &[Stmt]) -> HashMap<&str, &ruff_python_ast::StmtClassDef> {
    module
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::ClassDef(class) => Some((class.name.as_str(), class)),
            _ => None,
        })
        .collect()
}

/// Whether `candidate` is a transitive file-local ancestor of `class_name`;
/// cycles in the (invalid) inheritance graph are cut by the visited set.
fn has_file_local_ancestor(
    class_name: &str,
    candidate: &str,
    classes: &HashMap<&str, &ruff_python_ast::StmtClassDef>,
    visited: &mut HashSet<String>,
) -> bool {
    if !visited.insert(class_name.to_string()) {
        return false;
    }
    let Some(class) = classes.get(class_name) else {
        return false;
    };
    for base in direct_base_names(class) {
        if base == candidate || has_file_local_ancestor(base, candidate, classes, visited) {
            return true;
        }
    }
    false
}
