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
    let mut fixtures = std::collections::HashSet::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = *stmt
            && function.decorator_list.iter().any(|d| {
                let range = d.expression.range();
                let text = &source[range.start().to_usize()..range.end().to_usize()];
                text == "pytest.fixture" || text == "fixture"
            })
        {
            fixtures.insert(function.name.to_string());
        }
    }
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
                if name.contains("test")
                    && !name.starts_with("test")
                    && is_sonar_helper(function, &fixtures)
                {
                    issues.push(issue_at(
                        "python:S5899",
                        "Rename this method so that it starts with \"test\" or remove this unused helper.",
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

/// Sonar's helper predicate: no decorators, and every parameter is
/// `self`/`cls` or a known fixture name.
fn is_sonar_helper(
    function: &ruff_python_ast::StmtFunctionDef,
    fixtures: &std::collections::HashSet<String>,
) -> bool {
    if !function.decorator_list.is_empty() {
        return false;
    }
    let params = &function.parameters;
    params
        .posonlyargs
        .iter()
        .chain(&params.args)
        .chain(&params.kwonlyargs)
        .all(|param| {
            let name = param.parameter.name.as_str();
            name == "self" || name == "cls" || fixtures.contains(name)
        })
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
