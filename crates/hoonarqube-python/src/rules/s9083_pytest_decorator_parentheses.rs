use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{dotted_name_is, dotted_name_parent_in, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9083";
const REMOVE_MESSAGE: &str = "Remove empty parentheses from this decorator.";
const ADD_MESSAGE: &str = "Add empty parentheses to this decorator.";

/// python:S9083 — argument-free `@pytest.fixture` and `@pytest.mark.*`
/// decorators may omit parentheses; the reference check enforces one style
/// via the `requireParentheses` parameter. The default (`false`) flags the
/// empty-parentheses form `@pytest.fixture()` and anchors the empty
/// parentheses pair; a `true` configuration flags the bare form
/// `@pytest.fixture` and anchors the decorator expression. Decorators with
/// arguments and decorators outside the fixture/mark family stay silent.
pub(crate) fn check_s9083_pytest_decorator_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    require_parentheses: bool,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let decorators: &[Decorator] = match stmt {
            Stmt::FunctionDef(function) => &function.decorator_list,
            Stmt::ClassDef(class) => &class.decorator_list,
            _ => return,
        };
        for decorator in decorators {
            check_decorator(decorator, require_parentheses, index, source, &mut issues);
        }
    });
    issues
}

fn check_decorator(
    decorator: &Decorator,
    require_parentheses: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    match &decorator.expression {
        Expr::Call(call) => {
            if !require_parentheses
                && call.arguments.args.is_empty()
                && call.arguments.keywords.is_empty()
                && is_pytest_fixture_or_mark(&call.func)
            {
                issues.push(issue_at(
                    RULE_KEY,
                    REMOVE_MESSAGE,
                    call.arguments.range(),
                    index,
                    source,
                ));
            }
        }
        expression => {
            if require_parentheses && is_pytest_fixture_or_mark(expression) {
                issues.push(issue_at(
                    RULE_KEY,
                    ADD_MESSAGE,
                    expression.range(),
                    index,
                    source,
                ));
            }
        }
    }
}

/// `pytest.fixture`, the `pytest.mark` qualifier itself, and every mark
/// accessed on it (known marks have no separate stub requirement: the
/// qualifier decides).
fn is_pytest_fixture_or_mark(expr: &Expr) -> bool {
    dotted_name_is(expr, "pytest.fixture")
        || dotted_name_is(expr, "pytest.mark")
        || dotted_name_parent_in(expr, &["pytest.mark"])
}
