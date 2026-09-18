use crate::engine::file_context::FileContext;
use crate::support::stmt_exprs;
use crate::support::visit_ifexp_branches;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

pub(crate) fn check_nested_conditional_expressions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        for expr in stmt_exprs(stmt) {
            visit_ifexp_branches(expr, false, &mut issues, index, source);
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s3358_flags_nested_conditional_expressions() {
        let flagged = scan("v = a if b else c if d else e\n");
        assert_eq!(findings(&flagged, "python:S3358").len(), 1);
        assert!(findings(&scan("v = a if b else e\n"), "python:S3358").is_empty());
    }

    #[test]
    fn s3358_exempts_nested_conditionals_in_comprehension_elements() {
        // Issue #635: Sonar's NestedConditionalExpressionCheck exempts any
        // conditional with a comprehension ancestor, so even a genuinely
        // nested ternary inside a comprehension element is not flagged.
        let source = concat!(
            "def f(bases):\n",
            "    return tuple(\n",
            "        base.lower() if isinstance(base, str) else base\n",
            "        for base in bases\n",
            "    )\n",
            "\n",
            "def g(expressions):\n",
            "    return [\n",
            "        arg if hasattr(arg, \"resolve\") else (F(arg) if isinstance(arg, str) else V(arg))\n",
            "        for arg in expressions\n",
            "    ]\n",
        );
        assert!(findings(&scan(source), "python:S3358").is_empty());
    }

    #[test]
    fn s3358_exempts_nested_conditionals_in_comprehension_clauses() {
        // Comprehension `for`/`if` clauses are comprehension components too:
        // nested ternaries there stay exempt while the same shape in a plain
        // statement is still flagged.
        let exempt = scan("v = [x for x in (a if b else (c if d else e))]\n");
        assert!(findings(&exempt, "python:S3358").is_empty());
        let flagged = scan("v = a if b else (c if d else e)\n");
        assert_eq!(findings(&flagged, "python:S3358").len(), 1);
    }
}
