use crate::support::for_each_stmt_expr;
use crate::support::is_constant_expression;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_dict_comprehension_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::DictComp(comp) = expr
            && is_constant_expression(&comp.value)
        {
            issues.push(issue_at(
                "python:S7506",
                "Use 'dict.fromkeys' to build a mapping with a constant value.",
                comp.value.range(),
                index,
                source,
            ));
        }
    });
    issues
}
