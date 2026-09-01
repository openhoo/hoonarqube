//! Independently implemented non-Sonar Python rules.

use std::collections::HashSet;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

use crate::support::{
    called_name, child_bodies, collect_target_names, for_each_expr, for_each_stmt,
    for_each_stmt_expr_in_scope, for_each_stmt_in_scope, issue_at, parse, stmt_store_names,
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
    issues.extend(requests_without_timeout(
        &parsed,
        &index,
        source,
        &RequestNames::collect(&parsed),
    ));
    issues.extend(files_not_closed(
        &parsed,
        &index,
        source,
        &FileOpenNames::collect(&parsed),
    ));
    issues
}

const REQUEST_METHODS: &[&str] = &[
    "delete", "get", "head", "options", "patch", "post", "put", "request",
];

#[derive(Clone, Default)]
struct RequestNames {
    direct: HashSet<String>,
    modules: HashSet<String>,
}

impl RequestNames {
    fn collect(parsed: &Parsed<ModModule>) -> Self {
        Self::default().with_scope(parsed.syntax().body.as_slice(), std::iter::empty())
    }

    fn for_function(&self, function: &StmtFunctionDef) -> Self {
        self.clone().with_scope(
            &function.body,
            function
                .parameters
                .iter()
                .map(|parameter| parameter.name().to_string()),
        )
    }

    fn with_scope(
        mut self,
        suite: &[Stmt],
        initial_shadows: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut shadowed: HashSet<String> = initial_shadows.into_iter().collect();
        for_each_stmt_in_scope(suite, &mut |stmt| {
            let mut recognized = Self::default();
            match stmt {
                Stmt::Import(import) => recognized.record_import(import),
                Stmt::ImportFrom(import) => recognized.record_import_from(import),
                _ => {}
            }
            self.direct.extend(recognized.direct.iter().cloned());
            self.modules.extend(recognized.modules.iter().cloned());
            shadowed.extend(
                stmt_store_names(stmt)
                    .into_iter()
                    .filter(|name| !recognized.contains(name)),
            );
        });
        for_each_stmt_expr_in_scope(suite, &mut |expr| {
            if let Expr::Named(named) = expr {
                let mut targets = Vec::new();
                collect_target_names(&named.target, &mut targets);
                shadowed.extend(targets);
            }
        });
        for name in shadowed {
            self.direct.remove(&name);
            self.modules.remove(&name);
        }
        self
    }

    fn contains(&self, name: &str) -> bool {
        self.direct.contains(name) || self.modules.contains(name)
    }

    fn record_import(&mut self, import: &ruff_python_ast::StmtImport) {
        self.modules.extend(
            import
                .names
                .iter()
                .filter(|alias| alias.name.as_str() == "requests")
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
        if import
            .module
            .as_ref()
            .is_none_or(|module| module.as_str() != "requests")
        {
            return;
        }
        self.direct.extend(
            import
                .names
                .iter()
                .filter(|alias| REQUEST_METHODS.contains(&alias.name.as_str()))
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

fn requests_without_timeout(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    module_names: &RequestNames,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_request_calls_in_scope(
        parsed.syntax().body.as_slice(),
        module_names,
        index,
        source,
        &mut issues,
    );
    visit_functions(parsed.syntax().body.as_slice(), &mut |function| {
        check_request_calls_in_scope(
            &function.body,
            &module_names.for_function(function),
            index,
            source,
            &mut issues,
        );
    });
    issues
}

fn check_request_calls_in_scope(
    suite: &[Stmt],
    names: &RequestNames,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for_each_stmt_expr_in_scope(suite, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        let recognized = match call.func.as_ref() {
            Expr::Name(name) => names.direct.contains(name.id.as_str()),
            Expr::Attribute(attribute) => {
                REQUEST_METHODS.contains(&attribute.attr.as_str())
                    && matches!(
                        attribute.value.as_ref(),
                        Expr::Name(module) if names.modules.contains(module.id.as_str())
                    )
            }
            _ => false,
        };
        if !recognized
            || call
                .arguments
                .keywords
                .iter()
                .any(|keyword| keyword.arg.is_none())
        {
            return;
        }
        let timeout = call.arguments.keywords.iter().find(|keyword| {
            keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "timeout")
        });
        if timeout.is_some_and(|keyword| !matches!(keyword.value, Expr::NoneLiteral(_))) {
            return;
        }
        issues.push(issue_at(
            "hoonarqube-python:request-without-timeout",
            "Set an explicit finite timeout on this requests call.",
            call.func.range(),
            index,
            source,
        ));
    });
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

#[derive(Clone, Default)]
struct FileOpenNames {
    direct: HashSet<String>,
    modules: HashSet<String>,
}

impl FileOpenNames {
    fn collect(parsed: &Parsed<ModModule>) -> Self {
        let mut names = Self::default();
        names.direct.insert("open".to_string());
        names.with_scope(parsed.syntax().body.as_slice(), std::iter::empty())
    }

    fn for_function(&self, function: &StmtFunctionDef) -> Self {
        self.clone().with_scope(
            &function.body,
            function
                .parameters
                .iter()
                .map(|parameter| parameter.name().to_string()),
        )
    }

    fn with_scope(
        mut self,
        suite: &[Stmt],
        initial_shadows: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut shadowed: HashSet<String> = initial_shadows.into_iter().collect();
        for_each_stmt_in_scope(suite, &mut |stmt| {
            let mut recognized = Self::default();
            match stmt {
                Stmt::Import(import) => recognized.record_import(import),
                Stmt::ImportFrom(import) => recognized.record_import_from(import),
                _ => {}
            }
            self.direct.extend(recognized.direct.iter().cloned());
            self.modules.extend(recognized.modules.iter().cloned());
            shadowed.extend(
                stmt_store_names(stmt)
                    .into_iter()
                    .filter(|name| !recognized.contains(name)),
            );
        });
        for_each_stmt_expr_in_scope(suite, &mut |expr| {
            if let Expr::Named(named) = expr {
                let mut targets = Vec::new();
                collect_target_names(&named.target, &mut targets);
                shadowed.extend(targets);
            }
        });
        for name in shadowed {
            self.direct.remove(&name);
            self.modules.remove(&name);
        }
        self
    }

    fn contains(&self, name: &str) -> bool {
        self.direct.contains(name) || self.modules.contains(name)
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
    let open_names = open_names.for_function(function);
    for binding in collect_open_bindings(function, &open_names) {
        if !binding_is_closed_or_escaped(function, &binding) {
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

fn binding_is_closed_or_escaped(function: &StmtFunctionDef, binding: &OpenBinding) -> bool {
    let lifetime_end = next_binding_write_end(function, binding);
    let within_lifetime = |range: TextRange| {
        range.start() > binding.range.start() && lifetime_end.is_none_or(|end| range.start() < end)
    };
    let mut escaped = false;
    for_each_stmt_in_scope(&function.body, &mut |stmt| {
        if within_lifetime(stmt.range()) && statement_transfers_binding(stmt, &binding.name) {
            escaped = true;
        }
    });
    let mut closed = false;
    for_each_stmt_expr_in_scope(&function.body, &mut |expr| {
        if !within_lifetime(expr.range()) {
            return;
        }
        if is_close_call(expr, &binding.name) {
            closed = true;
        }
        if call_transfers_binding(expr, &binding.name) {
            escaped = true;
        }
    });
    closed || escaped || nested_scope_references(&function.body, &binding.name)
}

fn next_binding_write_end(function: &StmtFunctionDef, binding: &OpenBinding) -> Option<TextSize> {
    let mut next = None;
    for_each_stmt_in_scope(&function.body, &mut |stmt| {
        if stmt.range().start() > binding.range.start()
            && stmt_store_names(stmt)
                .iter()
                .any(|name| name == &binding.name)
        {
            next = Some(next.map_or(stmt.range().end(), |current: TextSize| {
                current.min(stmt.range().end())
            }));
        }
    });
    for_each_stmt_expr_in_scope(&function.body, &mut |expr| {
        if let Expr::Named(named) = expr
            && expr.range().start() > binding.range.start()
        {
            let mut targets = Vec::new();
            collect_target_names(&named.target, &mut targets);
            if targets.iter().any(|name| name == &binding.name) {
                next = Some(next.map_or(expr.range().end(), |current: TextSize| {
                    current.min(expr.range().end())
                }));
            }
        }
    });
    next
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

        let edge_cases = keys(concat!(
            "def custom(open):\n",
            "    handle = open('not-a-file')\n",
            "def order(handle):\n",
            "    handle.close()\n",
            "    handle = open('data')\n",
            "def reopened():\n",
            "    handle = open('first')\n",
            "    handle.close()\n",
            "    handle = open('second')\n",
            "def local_import():\n",
            "    from gzip import open as gzip_open\n",
            "    handle = gzip_open('archive.gz')\n",
        ));
        assert_eq!(
            edge_cases
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-python:file-not-closed")
                .count(),
            3,
            "shadowed opens and lifetime ordering must be distinguished: {edge_cases:?}",
        );
    }

    #[test]
    fn file_rule_ignores_module_level_open_shadowing() {
        let found = keys(concat!(
            "def open(path):\n",
            "    return Resource(path)\n",
            "def custom():\n",
            "    handle = open('not-a-file')\n",
        ));
        assert!(
            found.is_empty(),
            "shadowed builtin must stay clean: {found:?}"
        );
    }

    #[test]
    fn requests_rule_requires_resolved_requests_api_and_known_timeout() {
        let found = keys(concat!(
            "import requests as http\n",
            "from requests import post as submit\n",
            "http.get('https://example.test')\n",
            "submit('https://example.test', timeout=None)\n",
        ));
        assert_eq!(
            found
                .iter()
                .filter(|key| key.as_str() == "hoonarqube-python:request-without-timeout")
                .count(),
            2,
        );

        for clean in [
            "import requests\nrequests.get('https://example.test', timeout=5)",
            "import requests\nrequests.get('https://example.test', **options)",
            "def custom(requests):\n    requests.get('local')",
            "class Client:\n    def get(self, url): return url\nClient().get('local')",
            "import httpx\nhttpx.get('https://example.test')",
            "from requests import Session\nSession().get('https://example.test')",
        ] {
            assert!(
                !keys(clean)
                    .iter()
                    .any(|key| key == "hoonarqube-python:request-without-timeout"),
                "{clean}",
            );
        }
    }
}
