use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_notimplemented_raises(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && PROTOCOL_DUNDERS.contains(&function.name.as_str())
        {
            for_each_stmt_in_scope(&function.body, &mut |inner| {
                if let Stmt::Raise(raised) = inner
                    && raised
                        .exc
                        .as_deref()
                        .is_some_and(is_notimplemented_error_expr)
                {
                    issues.push(issue_at(
                        "python:S5712",
                        "Return 'NotImplemented' instead of raising 'NotImplementedError'.",
                        raised.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}

// --- migrated from support/mod.rs (S5712) ---
// --- python:S5712 — special methods raising NotImplementedError ---------------

pub(crate) const PROTOCOL_DUNDERS: [&str; 34] = [
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__or__",
    "__xor__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__ror__",
    "__rxor__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__hash__",
];

pub(crate) fn is_notimplemented_error_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => name.id.as_str() == "NotImplementedError",
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "NotImplementedError")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5712_prefers_returning_notimplemented() {
        let flagged =
            scan("class P:\n    def __eq__(self, other):\n        raise NotImplementedError\n");
        assert_eq!(findings(&flagged, "python:S5712").len(), 1);
        let clean = "class P:\n    def __eq__(self, other):\n        return NotImplemented\n";
        assert!(findings(&scan(clean), "python:S5712").is_empty());
    }
}
