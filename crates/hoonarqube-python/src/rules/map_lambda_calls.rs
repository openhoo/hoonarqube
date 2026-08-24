use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7505 — map with lambda ----------------------------------------------

pub(crate) fn check_map_lambda_calls(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) == Some("map")
            && call
                .arguments
                .args
                .first()
                .is_some_and(|first| matches!(first, Expr::Lambda(_)))
        {
            issues.push(issue_at(
                "python:S7505",
                "Replace this 'map' call with a comprehension.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7505_flags_map_with_leading_lambda() {
        let flagged = scan("names = map(lambda user: user.name, users)\n");
        let found = findings(&flagged, "python:S7505");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }

    #[test]
    fn s7505_flags_multiline_map_call_at_start_line() {
        let flagged = scan("scaled = map(\n    lambda x: x * factor,\n    values,\n)\n");
        let found = findings(&flagged, "python:S7505");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
    }

    #[test]
    fn s7505_ignores_other_callables_and_names() {
        for clean in [
            "kept = map(str.strip, rows)\n",
            "mapped = custom_map(lambda v: v + 1, data)\n",
            "lazy = map()\n",
        ] {
            assert!(findings(&scan(clean), "python:S7505").is_empty(), "{clean}");
        }
    }
}
