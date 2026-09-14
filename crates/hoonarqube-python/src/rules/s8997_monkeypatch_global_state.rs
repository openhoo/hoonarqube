use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::child_bodies;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8997";
const MESSAGE: &str = "Use the \"monkeypatch\" fixture for temporary modifications instead of manually modifying global state.";

/// python:S8997 — a test function that assigns through an imported
/// module (`requests.sessions.get_netrc_auth = ...`,
/// `os.environ["NETRC"] = ...`) manually edits global state that
/// outlives the test instead of delegating the save/restore to the
/// `monkeypatch` fixture. The assignment target anchors the finding.
/// Writes rooted at locals (`s.auth = ...`) are instance state, and
/// helper or nested definitions do not run test state edits themselves.
pub(crate) fn check_s8997_monkeypatch_global_state(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    if !is_pytest_file_name(path) {
        return Vec::new();
    }
    let module = parsed.syntax();
    let imports = imported_module_names(module.body.as_slice());
    let mut issues = Vec::new();
    walk_s8997(
        module.body.as_slice(),
        &imports,
        index,
        source,
        false,
        &mut issues,
    );
    issues
}

/// Plain and aliased `import` bindings of the file; the first segment
/// of a dotted import names the module that owns the state.
fn imported_module_names(stmts: &[Stmt]) -> Vec<&str> {
    let mut roots = Vec::new();
    for stmt in stmts {
        if let Stmt::Import(import) = stmt {
            for alias in &import.names {
                let bound = alias
                    .asname
                    .as_ref()
                    .map_or_else(|| alias.name.as_str(), |asname| asname.as_str());
                let root = bound.split('.').next().unwrap_or(bound);
                roots.push(root);
            }
        }
    }
    roots
}

/// Walks statements with the nearest enclosing `test*` function flag;
/// nested and class-level definitions are their own scopes, while the
/// bodies of compound statements run in the enclosing test.
fn walk_s8997(
    stmts: &[Stmt],
    imports: &[&str],
    index: &LineIndex,
    source: &str,
    in_test: bool,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let nested = function.name.as_str().starts_with("test");
                walk_s8997(
                    function.body.as_slice(),
                    imports,
                    index,
                    source,
                    nested,
                    issues,
                );
            }
            Stmt::ClassDef(class) => {
                walk_s8997(class.body.as_slice(), imports, index, source, false, issues);
            }
            other => {
                check_s8997_statement(other, in_test, imports, index, source, issues);
                for body in child_bodies(other) {
                    walk_s8997(body, imports, index, source, in_test, issues);
                }
            }
        }
    }
}

/// The statement-level half of the walker: in a test, plain and
/// augmented assignments are checked for module-state targets.
fn check_s8997_statement(
    stmt: &Stmt,
    in_test: bool,
    imports: &[&str],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !in_test {
        return;
    }
    match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                report_module_state_target(target, imports, index, source, issues);
            }
        }
        Stmt::AugAssign(aug_assign) => {
            report_module_state_target(&aug_assign.target, imports, index, source, issues);
        }
        _ => {}
    }
}

/// Reports Attribute and Subscript targets rooted at an imported module
/// name; tuple and list unpacking components are flattened. The whole
/// target anchors the finding.
fn report_module_state_target(
    target: &Expr,
    imports: &[&str],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    match target {
        Expr::Attribute(_) => {
            if attribute_root_is_imported(target, imports) {
                issues.push(issue_at(RULE_KEY, MESSAGE, target.range(), index, source));
            }
        }
        Expr::Subscript(subscript) => {
            if attribute_root_is_imported(&subscript.value, imports) {
                issues.push(issue_at(RULE_KEY, MESSAGE, target.range(), index, source));
            }
        }
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                report_module_state_target(element, imports, index, source, issues);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                report_module_state_target(element, imports, index, source, issues);
            }
        }
        _ => {}
    }
}

/// Whether the attribute chain terminates at a plain name that an
/// `import` statement of the file binds.
fn attribute_root_is_imported(expr: &Expr, imports: &[&str]) -> bool {
    let mut current = expr;
    loop {
        match current {
            Expr::Attribute(attribute) => current = attribute.value.as_ref(),
            Expr::Name(name) => return imports.contains(&name.id.as_str()),
            _ => return false,
        }
    }
}
