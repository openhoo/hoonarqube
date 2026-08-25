use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unreachable_test_methods(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::ClassDef(class) = stmt else {
            continue;
        };
        if !class.bases().iter().any(is_test_case_base) {
            continue;
        }
        for member in &class.body {
            if let Stmt::FunctionDef(function) = member {
                let name = function.name.as_str();
                if name.contains("test") && !name.starts_with("test") {
                    issues.push(issue_at(
                        "python:S5899",
                        "Rename this method to start with 'test' or remove it; test runners will not discover it.",
                        function.name.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

// --- python:S5899 — unreachable test methods ------------------------------------

fn is_test_case_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(tail, Some(base) if base.ends_with("TestCase"))
}
