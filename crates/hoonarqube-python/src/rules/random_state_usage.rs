use crate::support::dotted_name;
use crate::support::for_each_expr_in_module;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6711 — RandomState instead of default_rng ---------------------------

pub(crate) fn check_random_state_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        // Call callees are Attributes themselves, so matching Attribute nodes
        // alone covers both references and constructor invocations exactly once.
        if matches!(expr, Expr::Attribute(_))
            && matches!(
                dotted_name(expr).as_deref(),
                Some("np.random.RandomState" | "numpy.random.RandomState")
            )
        {
            issues.push(issue_at(
                "python:S6711",
                "Use numpy.random.default_rng instead of RandomState.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
