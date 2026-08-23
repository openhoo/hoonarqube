use crate::support::for_each_stmt;
use crate::support::has_file_local_ancestor;
use crate::support::issue_at;
use crate::support::module_classes;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
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
