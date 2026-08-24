use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4502 — CSRF protections should not be disabled -------------------

pub(crate) fn check_s4502_csrf_disabled(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            for decorator in &function.decorator_list {
                if matches!(&decorator.expression, Expr::Name(name) if name.id.as_str() == "csrf_exempt")
                {
                    issues.push(issue_at(
                        "python:S4502",
                        "Make sure that disabling CSRF protection is safe here.",
                        decorator.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4502_flags_csrf_exempt_decorators() {
        let flagged = "@csrf_exempt\ndef view(request):\n    return None\n";
        assert_eq!(findings(&scan(flagged), "python:S4502").len(), 1);
        let clean = "@login_required\ndef view(request):\n    return None\n";
        assert!(findings(&scan(clean), "python:S4502").is_empty());
    }
}
