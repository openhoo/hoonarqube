use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtClassDef, StmtFunctionDef};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

use crate::engine::file_context::FileContext;
use crate::engine::scope::DefFlavor;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::scope_is_within;
use crate::support::is_dunder_name;
use crate::support::is_test_scope_file;
use crate::support::issue_at;

// --- python:S1172 — unused function parameters -------------------------------

/// AWS Lambda handler entry points receive `event`/`context` by contract.
const AWS_LAMBDA_PARAMETERS: [&str; 2] = ["event", "context"];

pub(crate) fn check_unused_parameters(
    table: &SymbolTable,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    path: &Path,
) -> Vec<Issue> {
    // Sonar skips every function in `test*`/`conftest*` files outright.
    if is_test_scope_file(path) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for site in &table.def_sites {
        if site.flavor != DefFlavor::Function || site.decorated {
            continue;
        }
        let Some(function) = function_for_site(file_ctx, site.name_range) else {
            continue;
        };
        if function_is_exempt(
            table,
            file_ctx,
            site.own_scope,
            site.name.as_str(),
            site.name_range,
            function,
        ) {
            continue;
        }
        for (param_name, param_range) in &site.params {
            if is_ignored_parameter(param_name) {
                continue;
            }
            // A parameter is used when a load resolves to this function's
            // own scope. Same-name tokens elsewhere in the file (other
            // functions, annotations, unrelated scopes) must not veto the
            // finding, so no file-wide token fallback runs here.
            let used = table
                .resolved_loads
                .iter()
                .any(|load| load.target == Some(site.own_scope) && load.name == *param_name);
            if !used && !parameter_is_documented(source, file_ctx, function, param_name) {
                issues.push(issue_at(
                    "python:S1172",
                    &format!("Remove the unused function parameter \"{param_name}\"."),
                    *param_range,
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

fn function_for_site<'a>(
    file_ctx: &'a FileContext<'a>,
    name_range: TextRange,
) -> Option<&'a StmtFunctionDef> {
    file_ctx
        .functions
        .iter()
        .copied()
        .find(|function| function.name.range() == name_range)
}

/// The reference implementation's `isException` gate, reduced to the in-file
/// facts this analyzer can prove: special, test, override, and contract
/// shapes never report, because their signatures are fixed by convention.
fn function_is_exempt(
    table: &SymbolTable,
    file_ctx: &FileContext,
    own_scope: usize,
    name: &str,
    name_range: TextRange,
    function: &StmtFunctionDef,
) -> bool {
    // Dunder and test functions are contract code.
    if is_dunder_name(name) || name.starts_with("test") {
        return true;
    }
    // Methods whose inherited contract may already provide the member never
    // report: any transitive base that is not a class defined in the same
    // file is unresolved, and any in-file base defining the same member is a
    // genuine override.
    if can_override_in_file(file_ctx, name_range, name) {
        return true;
    }
    // `pass`/`raise`/string-or-ellipsis-only bodies declare a stub contract.
    if is_contract_body(&function.body) {
        return true;
    }
    // A lone `return NotImplemented` (or bare `return`) marks an
    // unimplemented contract, mirroring the reference's isNotImplemented.
    if returns_not_implemented(&function.body) {
        return true;
    }
    // A `locals()` call makes parameter presence observable.
    if scope_calls_locals(table, own_scope) {
        return true;
    }
    // A function used as a value (not only called) needs its signature.
    if has_non_call_usage(table, file_ctx, name, name_range) {
        return true;
    }
    false
}

fn find_owner_class<'a>(
    file_ctx: &'a FileContext<'a>,
    name_range: TextRange,
) -> Option<&'a StmtClassDef> {
    file_ctx
        .classes
        .iter()
        .copied()
        .find(|class| owns_method(class, name_range))
}

fn owns_method(class: &StmtClassDef, name_range: TextRange) -> bool {
    class.body.iter().any(
        |stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.range() == name_range),
    )
}

fn class_defines_member(class: &StmtClassDef, member: &str) -> bool {
    class
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.as_str() == member))
}

fn base_names(class: &StmtClassDef) -> Vec<&str> {
    let Some(arguments) = class.arguments.as_deref() else {
        return Vec::new();
    };
    arguments
        .args
        .iter()
        .filter_map(|base| base.as_name_expr())
        .map(|name| name.id.as_str())
        .chain(
            arguments
                .keywords
                .iter()
                .filter_map(|keyword| keyword.value.as_name_expr())
                .map(|name| name.id.as_str()),
        )
        .collect()
}

/// Mirrors the reference's canBeAnOverridingMethod reduced to in-file facts:
/// walking the owner's transitive bases, an unresolved (non-in-file) base
/// could provide the member, and an in-file base that defines it is a real
/// override. A method whose full in-file hierarchy lacks the member is judged
/// on its own body.
fn can_override_in_file(file_ctx: &FileContext, name_range: TextRange, member: &str) -> bool {
    let Some(owner) = find_owner_class(file_ctx, name_range) else {
        return false;
    };
    let mut pending: Vec<&str> = base_names(owner);
    let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
    while let Some(base_name) = pending.pop() {
        if !visited.insert(base_name) {
            continue;
        }
        let Some(base) = file_ctx
            .classes
            .iter()
            .copied()
            .find(|class| class.name.as_str() == base_name)
        else {
            return true;
        };
        if class_defines_member(base, member) {
            return true;
        }
        pending.extend(base_names(base));
    }
    false
}

/// The reference's interface-method shape: every top-level statement is
/// `pass`, `raise`, or an expression statement of string literals/ellipsis.
fn is_contract_body(body: &[Stmt]) -> bool {
    body.iter().all(|stmt| match stmt {
        Stmt::Pass(_) | Stmt::Raise(_) => true,
        Stmt::Expr(expression) => {
            matches!(
                &*expression.value,
                Expr::StringLiteral(_) | Expr::EllipsisLiteral(_)
            )
        }
        _ => false,
    })
}

/// A single `return NotImplemented` (or valueless `return`) statement.
fn returns_not_implemented(body: &[Stmt]) -> bool {
    let [Stmt::Return(return_stmt)] = body else {
        return false;
    };
    match return_stmt.value.as_deref() {
        None => true,
        Some(Expr::Name(name)) => name.id.as_str() == "NotImplemented",
        _ => false,
    }
}

/// Any `locals()` load inside the function's scope subtree, mirroring the
/// reference's containsCallToLocalsFunction.
fn scope_calls_locals(table: &SymbolTable, own_scope: usize) -> bool {
    table
        .resolved_loads
        .iter()
        .any(|load| load.name == "locals" && scope_is_within(table, load.scope, own_scope))
}

/// The reference's hasNonCallUsages: any in-file use of the function as a
/// value — outside a call callee — keeps the full signature meaningful.
fn has_non_call_usage(
    table: &SymbolTable,
    file_ctx: &FileContext,
    name: &str,
    name_range: TextRange,
) -> bool {
    table.resolved_loads.iter().any(|load| {
        load.name == name
            && load.range != name_range
            && !file_ctx
                .calls
                .iter()
                .any(|call| call.func.range().contains_range(load.range))
    })
}

fn is_ignored_parameter(name: &str) -> bool {
    name.starts_with('_') || matches!(name, "self" | "cls") || AWS_LAMBDA_PARAMETERS.contains(&name)
}

/// The reference's isUsedInStringLiteralOrComment: a bounded mention of the
/// parameter in the function's string literals or comments documents the
/// deliberate non-use (override contracts, DSL query strings).
fn parameter_is_documented(
    source: &str,
    file_ctx: &FileContext,
    function: &StmtFunctionDef,
    param_name: &str,
) -> bool {
    let range = function.range();
    let string_ranges: Vec<TextRange> = file_ctx
        .strings
        .iter()
        .map(ruff_text_size::Ranged::range)
        .filter(|literal| range.contains_range(*literal))
        .collect();
    for literal in &string_ranges {
        if boundary_mention(&source[*literal], param_name) {
            return true;
        }
    }
    // Comments are the '#' segments of the body that lie outside string
    // literals; string interiors were already checked above.
    let base = usize::from(range.start());
    let text = &source[range];
    for (index, _) in text.match_indices('#') {
        let absolute = TextSize::new(u32::try_from(base + index).unwrap_or(u32::MAX));
        if string_ranges
            .iter()
            .any(|literal| literal.contains(absolute))
        {
            continue;
        }
        let line_end = text[index..]
            .find('\n')
            .map_or(text.len(), |end| index + end);
        if boundary_mention(&text[index..line_end], param_name) {
            return true;
        }
    }
    false
}

/// Emulates the reference boundary regex `(^|\s+|"|'|@)name($|\s+|"|')`.
fn boundary_mention(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(found) = text[search..].find(name) {
        let start = search + found;
        let end = start + name.len();
        let before_ok = start == 0
            || matches!(
                bytes[start - 1],
                b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'@'
            );
        let after_ok =
            end == text.len() || matches!(bytes[end], b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'');
        if before_ok && after_ok {
            return true;
        }
        search = start + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, scan, scan_at};

    #[test]
    fn s1172_exempts_stub_override_and_documented_parameters() {
        // Raise-only interface stubs keep their parameter contracts.
        let stub = scan(concat!(
            "class Base:\n",
            "    def add_header(self, key, val):\n",
            "        \"\"\"Add a header.\"\"\"\n",
            "        raise NotImplementedError\n",
        ));
        assert!(findings(&stub, "python:S1172").is_empty());

        // Protocol stubs declared with an ellipsis body.
        let protocol = scan("class SupportsRead:\n    def read(self, length=-1): ...\n");
        assert!(findings(&protocol, "python:S1172").is_empty());

        // Dunder methods are contract methods.
        let dunder = scan(concat!(
            "class C:\n",
            "    def __exit__(self, exc_type, exc_value, traceback):\n",
            "        return False\n",
        ));
        assert!(findings(&dunder, "python:S1172").is_empty());

        // Methods of classes with bases may override the base contract.
        let overridable = scan(
            "class Handler(Exception):\n    def handle(self, payload):\n        return None\n",
        );
        assert!(findings(&overridable, "python:S1172").is_empty());

        // Sonar exempts test functions and test files.
        let test_fn = scan("def test_upload(url):\n    return None\n");
        assert!(findings(&test_fn, "python:S1172").is_empty());
        let test_file = scan_at(
            PathBuf::from("tests/test_requests.py"),
            "def check(url):\n    return None\n",
        );
        assert!(findings(&test_file, "python:S1172").is_empty());

        // A parameter documented in the body's strings is deliberate.
        let documented = scan(concat!(
            "def render(template, engine):\n",
            "    \"\"\"Render ``template``; engine is unused for now.\"\"\"\n",
            "    return template\n",
        ));
        assert!(findings(&documented, "python:S1172").is_empty());

        // Genuine unused parameters still fire.
        let genuine = scan("def scale(value, factor):\n    return value\n\n\nscale(2, 3)\n");
        assert_eq!(findings(&genuine, "python:S1172").len(), 1);
    }
}
