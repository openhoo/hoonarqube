use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::{WebFrameworkFacts, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5707 — "__cause__" must be an exception or None -----------------------

pub(crate) fn check_s5707_raise_from_non_exception(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let facts = WebFrameworkFacts::build(file_ctx);
    for stmt in &file_ctx.stmts {
        let cause = match stmt {
            Stmt::Raise(raise) => raise.cause.as_deref(),
            Stmt::Assign(assign) if assign.targets.iter().any(|target| matches!(target, Expr::Attribute(attribute) if attribute.attr.as_str() == "__cause__")) => Some(assign.value.as_ref()),
            _ => None,
        };
        if let Some(cause) = cause
            && known_non_exception(cause, &facts)
        {
            issues.push(issue_at(
                "python:S5707",
                "Replace this expression with an exception or None",
                cause.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn known_non_exception(cause: &Expr, facts: &WebFrameworkFacts<'_>) -> bool {
    if is_non_exception_literal(cause) {
        return true;
    }
    let Expr::Call(call) = cause else {
        return false;
    };
    let Some(function) = facts.resolve_function(call) else {
        return false;
    };
    let Some(annotation) = function.returns.as_deref() else {
        return false;
    };
    let known_builtin = matches!(annotation, Expr::Name(name) if matches!(name.id.as_str(), "str" | "int" | "float" | "bool" | "bytes" | "list" | "tuple" | "set" | "dict"));
    known_builtin || facts.expr_fqn(annotation).as_deref() == Some("traceback.TracebackException")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5707_flags_non_exception_raise_causes() {
        let bad = scan("raise ValueError('bad') from 42\n");
        assert_eq!(findings(&bad, "python:S5707").len(), 1);

        let good = scan("raise ValueError('bad') from KeyError('cause')\n");
        assert!(findings(&good, "python:S5707").is_empty());
    }
    #[test]
    fn remaining_s5707_checks_cause_assignments_and_known_return_types() {
        let report = scan(concat!(
            "import traceback\n",
            "def build() -> traceback.TracebackException:\n    return unknown\n",
            "def valid() -> BaseException:\n    return unknown\n",
            "error.__cause__ = build()\n",
            "error.__cause__ = 42\n",
            "error.__cause__ = None\n",
            "error.__cause__ = valid()\n",
            "error.__cause__ = unknown()\n",
        ));
        let issues = findings(&report, "python:S5707");
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start.line, 6);
        assert_eq!(issues[1].range.start.line, 7);
    }
}
