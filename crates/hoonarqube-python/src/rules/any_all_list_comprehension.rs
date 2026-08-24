use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7492 — materialized list passed to any/all -----------------------------

pub(crate) fn check_any_all_list_comprehension(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if matches!(dotted_name(&call.func).as_deref(), Some("any" | "all"))
            && let [only] = &call.arguments.args[..]
            && matches!(only, Expr::ListComp(_))
        {
            issues.push(issue_at(
                "python:S7492",
                "Pass a generator expression instead of a materialized list.",
                only.range(),
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
    fn s7492_prefers_generator_expressions_for_any_all() {
        let flagged = scan("any([x for x in xs])\nany(x for x in xs)\n");
        assert_eq!(findings(&flagged, "python:S7492").len(), 1);
    }
}
