use crate::support::collect_dataframe_variables;
use crate::support::for_each_expr_in_module;
use crate::support::issue_at;
use crate::support::receiver_root;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_dataframe_values_attribute(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let dataframes = collect_dataframe_variables(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Attribute(attribute) = expr
            && attribute.attr.as_str() == "values"
            && receiver_root(&attribute.value)
                .is_some_and(|root| dataframes.iter().any(|n| n == root))
        {
            issues.push(issue_at(
                "python:S6741",
                "Use to_numpy() instead of values on DataFrames.",
                attribute.range(),
                index,
                source,
            ));
        }
    });
    issues
}
