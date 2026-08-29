use crate::engine::file_context::FileContext;
use crate::support::dotted_name_is;
use crate::support::has_keyword;
use crate::support::is_zero_number_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashSet;

// --- python:S6727 — math.isclose against zero without abs_tol -------------------

pub(crate) fn check_isclose_zero_tolerance(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // `from math import isclose [as ic]` binds bare spellings; `import math
    // [as m]` binds module aliases. Star imports never bind, matching
    // sibling rules' explicit-name import handling.
    let (isclose_binds, math_aliases) = isclose_imports(&file_ctx.stmts);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if calls_isclose(&call.func, &isclose_binds, &math_aliases)
            && compares_zero_without_absolute_tolerance(call)
        {
            issues.push(issue_at(
                "python:S6727",
                "Add an abs_tol to compare this value against zero precisely.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn isclose_imports<'a>(stmts: &'a [&Stmt]) -> (HashSet<&'a str>, HashSet<&'a str>) {
    let mut isclose_binds = HashSet::new();
    let mut math_aliases = HashSet::new();
    for stmt in stmts {
        match stmt {
            Stmt::ImportFrom(import_from) => {
                collect_isclose_bindings(import_from, &mut isclose_binds);
            }
            Stmt::Import(import) => collect_math_aliases(import, &mut math_aliases),
            _ => {}
        }
    }
    (isclose_binds, math_aliases)
}

fn collect_isclose_bindings<'a>(
    import: &'a ruff_python_ast::StmtImportFrom,
    bindings: &mut HashSet<&'a str>,
) {
    if import
        .module
        .as_ref()
        .is_none_or(|module| module.as_str() != "math")
    {
        return;
    }
    for alias in &import.names {
        if alias.name.as_str() == "isclose" {
            bindings.insert(alias.asname.as_deref().unwrap_or("isclose"));
        }
    }
}

fn collect_math_aliases<'a>(
    import: &'a ruff_python_ast::StmtImport,
    aliases: &mut HashSet<&'a str>,
) {
    for alias in &import.names {
        if alias.name.as_str() == "math" {
            aliases.insert(alias.asname.as_deref().map_or("math", |asname| asname));
        }
    }
}

fn calls_isclose(func: &Expr, isclose_binds: &HashSet<&str>, math_aliases: &HashSet<&str>) -> bool {
    if dotted_name_is(func, "math.isclose") {
        return true;
    }
    match func {
        Expr::Name(name) => isclose_binds.contains(name.id.as_str()),
        Expr::Attribute(attr) => {
            attr.attr.as_str() == "isclose"
                && match attr.value.as_ref() {
                    Expr::Name(base) => math_aliases.contains(base.id.as_str()),
                    _ => false,
                }
        }
        _ => false,
    }
}

fn compares_zero_without_absolute_tolerance(call: &ruff_python_ast::ExprCall) -> bool {
    let compares_zero = call.arguments.args.iter().any(is_zero_number_literal)
        || keyword_value(&call.arguments, "rel_tol").is_some_and(is_zero_number_literal);
    compares_zero && !has_keyword(&call.arguments, "abs_tol")
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6727_flags_import_bound_isclose_spellings() {
        let qualified = scan("import math\nratio = math.isclose(a, 0)\n");
        assert_eq!(findings(&qualified, "python:S6727").len(), 1);
        let from_imported = scan("from math import isclose\nratio = isclose(a, 0)\n");
        assert_eq!(findings(&from_imported, "python:S6727").len(), 1);
        let aliased_from_import = scan("from math import isclose as same\nsame(a, 0)\n");
        assert_eq!(findings(&aliased_from_import, "python:S6727").len(), 1);
        let aliased_module = scan("import math as m\nm.isclose(a, 0)\n");
        assert_eq!(findings(&aliased_module, "python:S6727").len(), 1);
        let clean = scan("from cmath import isclose\nisclose(a, 0)\n");
        assert!(findings(&clean, "python:S6727").is_empty());
    }
}
