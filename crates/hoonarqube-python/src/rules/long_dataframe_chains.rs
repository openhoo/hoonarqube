use crate::support::collect_dataframe_variables;
use crate::support::for_each_stmt;
use crate::support::stmt_exprs;
use crate::support::visit_dataframe_chain;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_long_dataframe_chains(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let dataframes = collect_dataframe_variables(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            visit_dataframe_chain(expr, &dataframes, &mut issues, index, source);
        }
    });
    issues
}
