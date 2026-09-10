use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ExceptHandler, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5708 — caught values derive from BaseException ------------------------

pub(crate) fn check_s5708_excepting_non_exceptions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Try(try_) = stmt {
            for handler in &try_.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                let Some(handled) = inner.type_.as_ref() else {
                    continue;
                };
                let literal = is_non_exception_literal(handled);
                if !literal
                    && (!matches!(handled.as_ref(), ruff_python_ast::Expr::Name(_))
                        || !crate::quickfix::bindings::should_report_s5708(
                            parsed,
                            source,
                            handled.range(),
                        ))
                {
                    continue;
                }
                let issue = issue_at(
                    "python:S5708",
                    "Change this expression to be a class deriving from BaseException or a tuple of such classes.",
                    handled.range(),
                    index,
                    source,
                );
                let alternatives =
                    crate::quickfix::bindings::alternatives_s5708(parsed, index, source, &issue);
                let issue = alternatives.into_iter().fold(issue, |issue, alternative| {
                    issue.with_alternative(
                        alternative.id,
                        alternative.fix.message,
                        alternative.fix.edits,
                    )
                });
                issues.push(issue);
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5708_flags_literal_except_targets() {
        let bad = scan("try:\n    work()\nexcept 42:\n    recover()\n");
        assert_eq!(findings(&bad, "python:S5708").len(), 1);

        let good = scan("try:\n    work()\nexcept ValueError:\n    recover()\n");
        assert!(findings(&good, "python:S5708").is_empty());
        let local_unknown =
            scan("class E(External):\n    pass\ntry:\n    work()\nexcept E:\n    recover()\n");
        assert!(findings(&local_unknown, "python:S5708").is_empty());

        let local_plain = scan("class E:\n    pass\ntry:\n    work()\nexcept E:\n    recover()\n");
        let plain_findings = findings(&local_plain, "python:S5708");
        assert_eq!(plain_findings.len(), 1);
        assert_eq!(
            plain_findings[0]
                .alternatives
                .iter()
                .map(|alternative| alternative.id.as_str())
                .collect::<Vec<_>>(),
            vec!["s5708-add-exception-base"]
        );

        let builtin_non_exception = scan("try:\n    work()\nexcept int:\n    recover()\n");
        let builtin_findings = findings(&builtin_non_exception, "python:S5708");
        assert_eq!(builtin_findings.len(), 1);
        assert!(builtin_findings[0].alternatives.is_empty());
        let metaclass =
            scan("class E(metaclass=M):\n    pass\ntry:\n    work()\nexcept E:\n    recover()\n");
        let metaclass_findings = findings(&metaclass, "python:S5708");
        assert_eq!(metaclass_findings.len(), 1);
        assert!(metaclass_findings[0].alternatives.is_empty());
    }
}
