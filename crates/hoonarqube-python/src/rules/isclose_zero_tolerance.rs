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
    let mut isclose_binds: HashSet<&str> = HashSet::new();
    let mut math_aliases: HashSet<&str> = HashSet::new();
    for stmt in &file_ctx.stmts {
        match stmt {
            Stmt::ImportFrom(import_from) => {
                if import_from
                    .module
                    .as_ref()
                    .is_none_or(|module| module.as_str() != "math")
                {
                    continue;
                }
                for alias in &import_from.names {
                    if alias.name.as_str() == "isclose" {
                        isclose_binds.insert(alias.asname.as_deref().unwrap_or("isclose"));
                    }
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    if alias.name.as_str() == "math" {
                        math_aliases
                            .insert(alias.asname.as_deref().map_or("math", |asname| asname));
                    }
                }
            }
            _ => {}
        }
    }
    let calls_isclose = |func: &Expr| {
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
    };

    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !calls_isclose(&call.func) {
            continue;
        }
        let compares_zero = call.arguments.args.iter().any(is_zero_number_literal)
            || keyword_value(&call.arguments, "rel_tol").is_some_and(is_zero_number_literal);
        if compares_zero && !has_keyword(&call.arguments, "abs_tol") {
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
