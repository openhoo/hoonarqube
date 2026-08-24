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

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6742_flags_dataframe_chains_at_the_length_limit() {
        let setup = "import pandas as pd\ndf = pd.read_csv('f.csv')\n";
        let below_limit = format!("{setup}df.fillna(0).dropna().head()\n");
        assert!(
            findings(&scan(&below_limit), "python:S6742").is_empty(),
            "{below_limit}"
        );

        let over_limit = format!("{setup}df.fillna(0).dropna().sort_values('a').head().to_csv()\n");
        let report = scan(&over_limit);
        let found = findings(&report, "python:S6742");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s6742_ignores_non_dataframe_receivers() {
        let other = "text.strip().lower().replace('a', 'b').title()\n";
        assert!(findings(&scan(other), "python:S6742").is_empty());
    }
}
