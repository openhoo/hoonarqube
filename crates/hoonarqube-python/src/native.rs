//! Independently implemented non-Sonar Python rules.

use std::collections::HashSet;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::{
    called_name, child_bodies, for_each_expr, for_each_stmt, for_each_stmt_expr_in_scope,
    for_each_stmt_in_scope, issue_at, parse,
};

/// Runs the native Python rules. Syntax-invalid source stays silent because
/// the Sonar-parity parsing rule already owns malformed input.
pub(crate) fn analyze(source: &str) -> Vec<Issue> {
    let parsed = parse(source);
    if !parsed.errors().is_empty() {
        return Vec::new();
    }
    let index = LineIndex::from_source_text(source);
    let mut issues = side_effects_in_asserts(&parsed, &index, source);
    issues.extend(files_not_closed(
        &parsed,
        &index,
        source,
        &FileOpenNames::collect(&parsed),
    ));
    issues
}

fn side_effects_in_asserts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Assert(assertion) = stmt else {
            return;
        };
        let mut culprit = None;
        for_each_expr(&assertion.test, &mut |expr| {
            if culprit.is_none() && expression_has_required_side_effect(expr) {
                culprit = Some(expr.range());
            }
        });
        if let Some(range) = culprit {
            issues.push(issue_at(
                "hoonarqube-python:side-effect-in-assert",
                "Move this side effect out of the assertion.",
                range,
                index,
                source,
            ));
        }
    });
    issues
}

fn expression_has_required_side_effect(expr: &Expr) -> bool {
    if matches!(expr, Expr::Named(_)) {
        return true;
    }
    let Expr::Call(call) = expr else {
        return false;
    };
    called_name(&call.func).is_some_and(|name| {
        matches!(
            name,
            "append"
                | "extend"
                | "insert"
                | "pop"
                | "remove"
                | "clear"
                | "update"
                | "add"
                | "discard"
                | "sort"
                | "reverse"
                | "write"
                | "writelines"
                | "flush"
                | "close"
                | "send"
                | "sendall"
                | "commit"
                | "rollback"
                | "call"
                | "run"
                | "Popen"
                | "check_call"
                | "check_output"
                | "unlink"
                | "rename"
                | "replace"
                | "mkdir"
                | "makedirs"
                | "rmdir"
                | "system"
                | "print"
                | "open"
        )
    })
}

#[derive(Default)]
struct FileOpenNames {
    direct: HashSet<String>,
    modules: HashSet<String>,
}

impl FileOpenNames {
    fn collect(parsed: &Parsed<ModModule>) -> Self {
        let mut names = Self::default();
        names.direct.insert("open".to_string());
        for stmt in &parsed.syntax().body {
            match stmt {
                Stmt::Import(import) => names.record_import(import),
                Stmt::ImportFrom(import) => names.record_import_from(import),
                _ => {}
            }
        }
        names
    }

    fn record_import(&mut self, import: &ruff_python_ast::StmtImport) {
        self.modules.extend(
            import
                .names
                .iter()
                .filter(|alias| is_file_module(alias.name.as_str()))
                .map(|alias| {
                    alias
                        .asname
                        .as_deref()
                        .map_or(alias.name.as_str(), |asname| asname)
                        .to_string()
                }),
        );
    }

    fn record_import_from(&mut self, import: &ruff_python_ast::StmtImportFrom) {
        if !import
            .module
            .as_ref()
            .is_some_and(|module| is_file_module(module.as_str()))
        {
            return;
        }
        self.direct.extend(
            import
                .names
                .iter()
                .filter(|alias| alias.name.as_str() == "open")
                .map(|alias| {
                    alias
                        .asname
                        .as_deref()
                        .map_or(alias.name.as_str(), |asname| asname)
                        .to_string()
                }),
        );
    }
}

fn is_file_module(name: &str) -> bool {
    matches!(name, "builtins" | "io" | "gzip" | "bz2" | "lzma")
}

fn files_not_closed(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    open_names: &FileOpenNames,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_functions(parsed.syntax().body.as_slice(), &mut |function| {
        check_function_files(function, index, source, open_names, &mut issues);
    });
    issues
}

fn visit_functions<'a>(suite: &'a [Stmt], visit: &mut impl FnMut(&'a StmtFunctionDef)) {
    for stmt in suite {
        if let Stmt::FunctionDef(function) = stmt {
            visit(function);
        }
        for body in child_bodies(stmt) {
            visit_functions(body, visit);
        }
    }
}

#[derive(Clone)]
struct OpenBinding {
    name: String,
    range: TextRange,
}

fn check_function_files(
    function: &StmtFunctionDef,
    index: &LineIndex,
    source: &str,
    open_names: &FileOpenNames,
    issues: &mut Vec<Issue>,
) {
    for binding in collect_open_bindings(function, open_names) {
        if !binding_is_closed_or_escaped(function, &binding.name) {
            issues.push(issue_at(
                "hoonarqube-python:file-not-closed",
                "Close this file or open it with a with statement.",
                binding.range,
                index,
                source,
            ));
        }
    }
}

fn collect_open_bindings(
    function: &StmtFunctionDef,
    open_names: &FileOpenNames,
) -> Vec<OpenBinding> {
    let mut bindings = Vec::new();
    for_each_stmt_in_scope(&function.body, &mut |stmt| match stmt {
        Stmt::Assign(assign) if assign.targets.len() == 1 => {
            if let Expr::Name(name) = &assign.targets[0]
                && is_file_open(&assign.value, open_names)
            {
                bindings.push(OpenBinding {
                    name: name.id.to_string(),
                    range: assign.value.range(),
                });
            }
        }
        Stmt::AnnAssign(assign) => {
            if let (Expr::Name(name), Some(value)) =
                (assign.target.as_ref(), assign.value.as_deref())
                && is_file_open(value, open_names)
            {
                bindings.push(OpenBinding {
                    name: name.id.to_string(),
                    range: value.range(),
                });
            }
        }
        _ => {}
    });
    bindings
}

fn binding_is_closed_or_escaped(function: &StmtFunctionDef, binding: &str) -> bool {
    let mut escaped = false;
    for_each_stmt_in_scope(&function.body, &mut |stmt| {
        if statement_transfers_binding(stmt, binding) {
            escaped = true;
        }
    });
    let mut closed = false;
    for_each_stmt_expr_in_scope(&function.body, &mut |expr| {
        if is_close_call(expr, binding) {
            closed = true;
        }
        if call_transfers_binding(expr, binding) {
            escaped = true;
        }
    });
    closed || escaped || nested_scope_references(&function.body, binding)
}

fn is_file_open(expr: &Expr, names: &FileOpenNames) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    match call.func.as_ref() {
        Expr::Name(name) => names.direct.contains(name.id.as_str()),
        Expr::Attribute(attribute) => {
            attribute.attr.as_str() == "open"
                && matches!(
                    attribute.value.as_ref(),
                    Expr::Name(module) if names.modules.contains(module.id.as_str())
                )
        }
        _ => false,
    }
}

fn is_close_call(expr: &Expr, binding: &str) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    matches!(
        call.func.as_ref(),
        Expr::Attribute(attribute)
            if attribute.attr.as_str() == "close"
                && matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == binding)
    )
}

fn call_transfers_binding(expr: &Expr, binding: &str) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    if is_close_call(expr, binding) {
        return false;
    }
    call.arguments
        .args
        .iter()
        .chain(call.arguments.keywords.iter().map(|keyword| &keyword.value))
        .any(|argument| expression_references_name(argument, binding))
}

fn statement_transfers_binding(stmt: &Stmt, binding: &str) -> bool {
    match stmt {
        Stmt::Return(return_) => return_
            .value
            .as_deref()
            .is_some_and(|value| returned_value_owns_binding(value, binding)),
        _ => false,
    }
}

fn returned_value_owns_binding(expr: &Expr, binding: &str) -> bool {
    match expr {
        Expr::Name(name) => name.id.as_str() == binding,
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .any(|item| returned_value_owns_binding(item, binding)),
        Expr::List(list) => list
            .elts
            .iter()
            .any(|item| returned_value_owns_binding(item, binding)),
        Expr::Set(set) => set
            .elts
            .iter()
            .any(|item| returned_value_owns_binding(item, binding)),
        Expr::Dict(dict) => dict.items.iter().any(|item| {
            item.key
                .as_ref()
                .is_some_and(|key| returned_value_owns_binding(key, binding))
                || returned_value_owns_binding(&item.value, binding)
        }),
        _ => false,
    }
}

fn expression_references_name(expr: &Expr, wanted: &str) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |candidate| {
        if matches!(candidate, Expr::Name(name) if name.id.as_str() == wanted) {
            found = true;
        }
    });
    found
}

fn nested_scope_references(suite: &[Stmt], wanted: &str) -> bool {
    let mut referenced = false;
    for stmt in suite {
        if let Stmt::FunctionDef(function) = stmt {
            crate::support::for_each_stmt_expr(&function.body, &mut |expr| {
                if matches!(expr, Expr::Name(name) if name.id.as_str() == wanted) {
                    referenced = true;
                }
            });
            continue;
        }
        for body in child_bodies(stmt) {
            if nested_scope_references(body, wanted) {
                referenced = true;
            }
        }
    }
    referenced
}

#[cfg(test)]
mod tests {
    use super::analyze;

    fn keys(source: &str) -> Vec<String> {
        analyze(source)
            .into_iter()
            .map(|issue| issue.rule_key)
            .collect()
    }

    #[test]
    fn assertion_rule_reports_only_known_required_side_effects() {
        let found = keys(concat!(
            "import subprocess\n",
            "assert subprocess.call(['backup']) == 0\n",
            "assert (cached := compute())\n",
            "assert len(items) > 0\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-python:side-effect-in-assert")
                .count(),
            2
        );
    }

    #[test]
    fn file_rule_is_conservative_about_close_and_ownership_transfer() {
        let found = keys(concat!(
            "def leaked():\n",
            "    handle = open('data')\n",
            "    return handle.read()\n",
            "def closed():\n",
            "    handle = open('data')\n",
            "    handle.close()\n",
            "def transferred():\n",
            "    handle = open('data')\n",
            "    return handle\n",
            "def passed():\n",
            "    handle = open('data')\n",
            "    consume(handle)\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-python:file-not-closed")
                .count(),
            1
        );

        let precise = keys(concat!(
            "import io as streams\n",
            "from gzip import open as gzip_open\n",
            "class Database:\n",
            "    def open(self, name): return name\n",
            "def examples(database):\n",
            "    custom = database.open('data')\n",
            "    first = streams.open('first')\n",
            "    second = gzip_open('second')\n",
        ));
        assert_eq!(
            precise
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-python:file-not-closed")
                .count(),
            2,
            "custom .open methods must stay clean: {precise:?}",
        );
    }
}
