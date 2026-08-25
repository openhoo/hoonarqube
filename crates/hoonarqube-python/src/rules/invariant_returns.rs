use crate::support::constant_truth;
use crate::support::expr_normalized_text;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_invariant_returns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            let returns = direct_constant_return_texts(&function.body, source);
            let identical = returns.len() >= 2 && returns.windows(2).all(|pair| pair[0] == pair[1]);
            if identical {
                issues.push(issue_at(
                    "python:S3516",
                    "Every return path yields the same constant; verify this is intended.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- migrated from support/mod.rs (S3516) ---
// --- python:S3516 — invariant function returns --------------------------------

/// Normalized texts of direct non-None constant `return` values.
fn direct_constant_return_texts(suite: &[Stmt], source: &str) -> Vec<String> {
    let mut texts = Vec::new();
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if let Stmt::Return(return_stmt) = stmt
            && let Some(value) = return_stmt.value.as_deref()
            && !is_none_literal(value)
            && constant_truth(value).is_some()
        {
            texts.push(expr_normalized_text(value, source));
        }
    });
    texts
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3516_flags_method_with_invariant_returns() {
        let flagged = scan("class C:\n    def m(self):\n        return 1\n        return 1\n");
        assert!(!findings(&flagged, "python:S3516").is_empty());
    }

    #[test]
    fn s3516_module_function_still_flagged() {
        let flagged = scan("def f():\n    return 1\n    return 1\n");
        assert!(!findings(&flagged, "python:S3516").is_empty());
    }
}
