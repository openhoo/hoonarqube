use ruff_python_ast::comparable::ComparableExpr;
use ruff_python_ast::{Decorator, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{dotted_name_is, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S9078";
const MESSAGE: &str = "Remove this duplicate test case.";

/// python:S9078 — a `@pytest.mark.parametrize` value list that repeats a case
/// executes the same scenario twice. Entries are compared structurally as
/// expressions (literals, names, calls, tuples), so `("T", "T")` duplicates
/// its twin while distinct names or calls stay silent. Each repeated entry
/// anchors its own finding; the first occurrence stays silent. Non-sequence
/// `argvalues` (generator calls, `product(...)`) and empty lists are other
/// rules' shapes and stay silent here.
pub(crate) fn check_s9078_duplicate_parametrize_cases(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let decorators: &[Decorator] = match stmt {
            Stmt::FunctionDef(function) => &function.decorator_list,
            Stmt::ClassDef(class) => &class.decorator_list,
            _ => return,
        };
        for decorator in decorators {
            check_decorator(decorator, index, source, &mut issues);
        }
    });
    issues
}

fn check_decorator(
    decorator: &Decorator,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Call(call) = &decorator.expression else {
        return;
    };
    if !dotted_name_is(&call.func, "pytest.mark.parametrize") {
        return;
    }
    let argvalues = call.arguments.args.get(1).or_else(|| {
        call.arguments
            .keywords
            .iter()
            .find(|keyword| keyword.arg.as_deref() == Some("argvalues"))
            .map(|keyword| &keyword.value)
    });
    let Some(entries) = argvalues else {
        return;
    };
    let entries: &[Expr] = match entries {
        Expr::List(list) => &list.elts,
        Expr::Tuple(tuple) => &tuple.elts,
        _ => return,
    };
    let mut distinct: Vec<ComparableExpr> = Vec::new();
    for entry in entries {
        let comparable = ComparableExpr::from(entry);
        if distinct.contains(&comparable) {
            issues.push(issue_at(RULE_KEY, MESSAGE, entry.range(), index, source));
        } else {
            distinct.push(comparable);
        }
    }
}
