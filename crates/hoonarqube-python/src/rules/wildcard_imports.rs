use crate::engine::file_context::AnyImport;
use crate::engine::file_context::FileContext;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::path::Path;

// --- python:S2208 — wildcard imports -----------------------------------------
//
// The reference never reports `__init__.py` (wildcard re-export is the
// idiom there) and only fires when the module contains application logic:
// function/class definitions, loops, `with`, augmented or non-`__all__`
// assignments, or calls other than `warnings.warn`.

pub(crate) fn check_wildcard_imports(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    path: &Path,
) -> Vec<Issue> {
    if path.file_name().is_some_and(|name| name == "__init__.py")
        || !contains_application_logic(parsed)
    {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for entry in &file_ctx.imports {
        let AnyImport::From(import) = entry else {
            continue;
        };
        if import.names.iter().any(|alias| alias.name.as_str() == "*") {
            issues.push(issue_at(
                "python:S2208",
                "Name the symbols to import explicitly instead of importing '*'.",
                import.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn contains_application_logic(parsed: &Parsed<ModModule>) -> bool {
    let mut found = false;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        match stmt {
            Stmt::FunctionDef(_)
            | Stmt::ClassDef(_)
            | Stmt::While(_)
            | Stmt::For(_)
            | Stmt::With(_)
            | Stmt::AugAssign(_) => found = true,
            Stmt::Assign(assign) => {
                found |= assign.targets.iter().any(
                    |target| !matches!(target, Expr::Name(name) if name.id.as_str() == "__all__"),
                );
            }
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            let mut pending = vec![expr];
            while let Some(expr) = pending.pop() {
                if let Expr::Call(call) = expr {
                    let is_warnings_warn = matches!(
                        call.func.as_ref(),
                        Expr::Attribute(attribute)
                            if attribute.attr.as_str() == "warn"
                                && matches!(attribute.value.as_ref(),
                                    Expr::Name(name) if name.id.as_str() == "warnings")
                    );
                    found |= !is_warnings_warn;
                }
                pending.extend(crate::support::child_exprs(expr));
            }
        }
    });
    found
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2208_flags_wildcard_imports() {
        // The reference only fires when the module contains application
        // logic; a bare wildcard re-export is clean.
        assert!(findings(&scan("from m import *\n"), "python:S2208").is_empty());
        assert_eq!(
            findings(
                &scan("from m import *\ndef f():\n    pass\n"),
                "python:S2208"
            )
            .len(),
            1
        );
        assert!(findings(&scan("from m import thing\n"), "python:S2208").is_empty());
    }
}
