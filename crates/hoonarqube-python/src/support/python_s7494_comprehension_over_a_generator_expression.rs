// --- python:S7494 — comprehension over a generator expression

use crate::support::{called_name, exprs_textually_equal, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

/// `(name, sole positional argument)` for calls shaped `name(x)` without
/// keywords.
pub(crate) fn single_positional_call<'a>(expr: &'a Expr, name: &str) -> Option<&'a Expr> {
    match expr {
        Expr::Call(call)
            if called_name(&call.func) == Some(name)
                && call.arguments.args.len() == 1
                && call.arguments.keywords.is_empty() =>
        {
            Some(&call.arguments.args[0])
        }
        _ => None,
    }
}

pub(crate) fn flag_copy_only(
    element: &Expr,
    generators: &[ruff_python_ast::Comprehension],
    range: TextRange,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let [generator] = generators else { return };
    if generator.ifs.is_empty() && exprs_textually_equal(element, &generator.target, source) {
        issues.push(issue_at(
            "python:S7500",
            "Copy the iterable directly instead of using a comprehension that only renames.",
            range,
            index,
            source,
        ));
    }
}
