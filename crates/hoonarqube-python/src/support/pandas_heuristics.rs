// --- pandas heuristics

use crate::support::{child_exprs, dotted_name, for_each_stmt, issue_at, receiver_root};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) const PANDAS_INPLACE_METHODS: [&str; 13] = [
    "reset_index",
    "drop",
    "dropna",
    "fillna",
    "ffill",
    "bfill",
    "sort_values",
    "sort_index",
    "rename",
    "replace",
    "set_index",
    "round",
    "clip",
];

/// Names bound directly to a DataFrame-shaped construction in this file.
pub(crate) fn collect_dataframe_variables(module_body: &[Stmt]) -> Vec<String> {
    const CONSTRUCTORS: [&str; 7] = [
        "pd.DataFrame",
        "pandas.DataFrame",
        "pd.read_csv",
        "pandas.read_csv",
        "DataFrame",
        "read_csv",
        "read_table",
    ];
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && dotted_name(&call.func).is_some_and(|path| CONSTRUCTORS.contains(&path.as_str()))
        {
            names.push(target.id.to_string());
        }
    });
    names
}

/// Number of consecutive attribute/method segments in a receiver chain.
pub(crate) fn method_chain_length(expr: &Expr) -> u32 {
    match expr {
        // Every `x.m` access is one hop; the surrounding `(...)` call merges
        // into that hop instead of adding another.
        Expr::Attribute(attribute) => 1 + method_chain_length(&attribute.value),
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Attribute(_) => method_chain_length(&call.func),
            _ => 1 + method_chain_length(&call.func),
        },
        _ => 0,
    }
}

/// Flags maximal DataFrame-rooted method chains beyond the RSPEC length.
pub(crate) fn visit_dataframe_chain(
    expr: &Expr,
    dataframes: &[String],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    const CHAIN_LIMIT: u32 = 4;
    let dataframe_rooted =
        receiver_root(expr).is_some_and(|root| dataframes.iter().any(|name| name == root));
    if dataframe_rooted && method_chain_length(expr) >= CHAIN_LIMIT {
        issues.push(issue_at(
            "python:S6742",
            "Break up this long method chain or use pipe().",
            expr.range(),
            index,
            source,
        ));
        return;
    }
    for child in child_exprs(expr) {
        visit_dataframe_chain(child, dataframes, issues, index, source);
    }
}
