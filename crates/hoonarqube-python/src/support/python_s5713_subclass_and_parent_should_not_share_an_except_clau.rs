// --- python:S5713 — subclass and parent should not share an except clause

use crate::AnalyzerOptions;
use crate::support::{child_bodies, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;
use std::collections::HashMap;
use std::collections::HashSet;

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

// ---------------------------------------------------------------------------
// Tier A — naming conventions (python:S100, python:S101, python:S116,
// python:S117, python:S1542).
// ---------------------------------------------------------------------------

/// Visits every function definition together with its lexical class-body
/// context: definitions written directly in a class body are methods,
/// everything else (module-level functions and functions nested inside other
/// functions) is not. This context partitions python:S100 from python:S1542.
pub(crate) fn for_each_function_def<'a>(
    stmts: &'a [Stmt],
    in_class_body: bool,
    visit: &mut impl FnMut(&'a ruff_python_ast::StmtFunctionDef, bool),
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                visit(function, in_class_body);
                for_each_function_def(&function.body, false, visit);
            }
            Stmt::ClassDef(class) => for_each_function_def(&class.body, true, visit),
            _ => {
                for body in child_bodies(stmt) {
                    for_each_function_def(body, in_class_body, visit);
                }
            }
        }
    }
}

/// `^[a-z_][a-z0-9_]*$` — shared shape of function, method, parameter and
/// local-variable names (python:S100/S1542/S117).
pub(crate) fn matches_snake_case(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}

/// `^_?([A-Z_][a-zA-Z0-9]*|[a-z_][a-z0-9_]*)$` — class names (python:S101).
pub(crate) fn matches_class_name(name: &str) -> bool {
    let rest = name.strip_prefix('_').unwrap_or(name);
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first.is_ascii_uppercase() || first == '_' {
        chars.all(|c| c.is_ascii_alphanumeric())
    } else {
        first.is_ascii_lowercase()
            && chars.all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
    }
}

/// `^[_a-z][_a-z0-9]*$` — class-body field names; unlike function and local
/// names no digit may directly follow the leading character (python:S116).
pub(crate) fn matches_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_lowercase() => {}
        _ => return false,
    }
    match chars.next() {
        None => true,
        Some(second) if second == '_' || second.is_ascii_lowercase() => {
            chars.all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Name leaves of an assignment-target tree (`a`, `a, b = ...`, `[a] = ...`).
pub(crate) fn binding_target_names(target: &Expr) -> Vec<&Expr> {
    match target {
        Expr::Name(_) => vec![target],
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(binding_target_names).collect(),
        Expr::List(list) => list.elts.iter().flat_map(binding_target_names).collect(),
        Expr::Starred(starred) => binding_target_names(&starred.value),
        _ => Vec::new(),
    }
}

/// All named parameters of a definition, including `*args` and `**kwargs`.
pub(crate) fn function_all_parameters(
    function: &ruff_python_ast::StmtFunctionDef,
) -> Vec<&ruff_python_ast::Identifier> {
    let parameters = &function.parameters;
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|parameter| &parameter.parameter.name)
        .chain(
            parameters
                .vararg
                .as_deref()
                .map(|parameter| &parameter.name),
        )
        .chain(parameters.kwarg.as_deref().map(|parameter| &parameter.name))
        .collect()
}

/// Bound name-bearing target expressions of a binding statement.
pub(crate) fn binding_stmt_targets(stmt: &Stmt) -> Vec<&Expr> {
    match stmt {
        Stmt::Assign(assign) => assign
            .targets
            .iter()
            .flat_map(binding_target_names)
            .collect(),
        Stmt::AnnAssign(assignment) => binding_target_names(&assignment.target),
        Stmt::AugAssign(assignment) => binding_target_names(&assignment.target),
        Stmt::For(loop_stmt) => binding_target_names(&loop_stmt.target),
        Stmt::With(with_stmt) => with_stmt
            .items
            .iter()
            .filter_map(|item| item.optional_vars.as_deref())
            .flat_map(binding_target_names)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn push_local_name_issue(
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
    name: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) {
    if !seen.insert(name.to_string()) || matches_snake_case(name) {
        return;
    }
    issues.push(issue_at(
        "python:S117",
        "Rename this local variable to match the regular expression '^[_a-z][a-z0-9_]*$'.",
        range,
        index,
        source,
    ));
}

/// Counts `return` statements in this function's own body; nested function
/// definitions are separate units with their own budgets.
pub(crate) fn count_own_returns(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .map(|stmt| match stmt {
            Stmt::Return(_) => 1,
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => 0,
            _ => child_bodies(stmt)
                .iter()
                .map(|body| count_own_returns(body))
                .sum(),
        })
        .sum()
}

/// Keyword introducing a python:S134 nesting construct.
fn nesting_keyword(stmt: &Stmt) -> Option<&'static str> {
    match stmt {
        Stmt::If(_) => Some("if"),
        Stmt::For(loop_stmt) => Some(if loop_stmt.is_async {
            "async for"
        } else {
            "for"
        }),
        Stmt::While(_) => Some("while"),
        Stmt::Try(_) => Some("try"),
        Stmt::With(with_stmt) => Some(if with_stmt.is_async {
            "async with"
        } else {
            "with"
        }),
        _ => None,
    }
}

fn flag_excess_nesting(
    stmt: &Stmt,
    level: u32,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let Some(keyword) = nesting_keyword(stmt) else {
        return;
    };
    if level <= options.maximum_nesting_depth {
        return;
    }
    let width = TextSize::try_from(keyword.len()).unwrap_or_default();
    issues.push(issue_at(
        "python:S134",
        &format!(
            "Refactor this code to not nest more than {} levels.",
            options.maximum_nesting_depth
        ),
        TextRange::at(stmt.start(), width),
        index,
        source,
    ));
}

/// Walks nesting constructs (If/For/While/Try/With), tracking depth. Elif
/// and else clauses share their `if`'s level; handler bodies share their
/// `try`'s level; nested definitions are units of their own and reset it.
pub(crate) fn walk_nesting_depth(
    stmts: &[Stmt],
    depth: u32,
    options: &AnalyzerOptions,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                walk_nesting_depth(&function.body, 0, options, issues, index, source);
            }
            Stmt::ClassDef(class) => {
                walk_nesting_depth(&class.body, 0, options, issues, index, source);
            }
            Stmt::If(if_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&if_stmt.body, depth + 1, options, issues, index, source);
                for clause in &if_stmt.elif_else_clauses {
                    walk_nesting_depth(&clause.body, depth + 1, options, issues, index, source);
                }
            }
            Stmt::For(loop_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&loop_stmt.body, depth + 1, options, issues, index, source);
                walk_nesting_depth(&loop_stmt.orelse, depth + 1, options, issues, index, source);
            }
            Stmt::While(while_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&while_stmt.body, depth + 1, options, issues, index, source);
                walk_nesting_depth(
                    &while_stmt.orelse,
                    depth + 1,
                    options,
                    issues,
                    index,
                    source,
                );
            }
            Stmt::Try(try_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&try_stmt.body, depth + 1, options, issues, index, source);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(inner) = handler;
                    walk_nesting_depth(&inner.body, depth + 1, options, issues, index, source);
                }
                walk_nesting_depth(&try_stmt.orelse, depth + 1, options, issues, index, source);
                walk_nesting_depth(
                    &try_stmt.finalbody,
                    depth + 1,
                    options,
                    issues,
                    index,
                    source,
                );
            }
            Stmt::With(with_stmt) => {
                flag_excess_nesting(stmt, depth + 1, options, issues, index, source);
                walk_nesting_depth(&with_stmt.body, depth + 1, options, issues, index, source);
            }
            _ => {}
        }
    }
}
