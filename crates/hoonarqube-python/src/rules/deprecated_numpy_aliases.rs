use crate::support::dotted_name;
use crate::support::for_each_expr_in_module;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_deprecated_numpy_aliases(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Attribute(_) = expr
            && dotted_name(expr).is_some_and(|p| DEPRECATED_NUMPY_ALIASES.contains(&p.as_str()))
        {
            issues.push(issue_at(
                "python:S6730",
                "Replace this deprecated NumPy alias with its modern equivalent.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S6730) ---
// --- python:S6730 — deprecated NumPy scalar aliases ------------------------------

const DEPRECATED_NUMPY_ALIASES: [&str; 16] = [
    "np.int",
    "np.float",
    "np.bool",
    "np.object",
    "np.str",
    "np.long",
    "np.unicode",
    "np.complex",
    "np.float_",
    "numpy.int",
    "numpy.float",
    "numpy.bool",
    "numpy.object",
    "numpy.str",
    "numpy.long",
    "numpy.complex",
];
