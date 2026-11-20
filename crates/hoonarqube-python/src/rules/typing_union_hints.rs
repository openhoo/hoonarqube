use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::{child_exprs_into, for_each_stmt, function_parameters, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::token::parenthesized_range;
use ruff_python_ast::{AnyNodeRef, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typing_union_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut check_annotation = |annotation: &Expr, parent: AnyNodeRef<'_>| {
        let mut pending = vec![annotation];
        while let Some(expr) = pending.pop() {
            if let Expr::Subscript(subscript) = expr
                && file_ctx
                    .known_bindings
                    .resolve_expr_identity(&subscript.value)
                    == KnownBinding::TypingUnion
            {
                // One diagnostic per annotation, even if it contains several unions.
                let range = parenthesized_range(annotation.into(), parent, parsed.tokens())
                    .unwrap_or_else(|| annotation.range());
                issues.push(issue_at(
                    "python:S6546",
                    "Use a union type expression for this type hint.",
                    range,
                    index,
                    source,
                ));
                break;
            }
            child_exprs_into(expr, &mut pending);
        }
    };
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => {
            let parameters = &function.parameters;
            let regular = function_parameters(function)
                .into_iter()
                .map(|entry| &entry.parameter);
            let variadic = [parameters.vararg.as_deref(), parameters.kwarg.as_deref()]
                .into_iter()
                .flatten();
            for parameter in regular.chain(variadic) {
                if let Some(annotation) = parameter.annotation.as_deref() {
                    check_annotation(annotation, stmt.into());
                }
            }
            if let Some(returns) = function.returns.as_deref() {
                check_annotation(returns, stmt.into());
            }
        }
        Stmt::AnnAssign(assign) => check_annotation(&assign.annotation, stmt.into()),
        _ => {}
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6546_prefers_pep604_unions() {
        let flagged = scan(
            "from typing import Union\ndef f(x: Union[int, str]) -> int:\n    return 1\ndef g(x: int | str) -> int:\n    return 1\n",
        );
        assert_eq!(findings(&flagged, "python:S6546").len(), 1);
    }

    #[test]
    fn s6546_reports_one_complete_annotation_for_each_typed_site() {
        let source = concat!(
            "from typing import Union as U\n",
            "import typing as t\n",
            "outer: tuple[t.Union[int, str], U[int, bytes]] = ()\n",
            "def f(*args: U[int, str], **kwargs: U[int, str]) -> (t.Union[int, str]):\n",
            "    local: list[U[int, str]] = []\n",
            "    return 1\n",
            "clean: list[int | str] = []\n",
            "value = U[int, str]\n",
            "def shadow(t):\n",
            "    annotation: t.Union[int, str] = 1\n",
        );
        let issues = scan(source);
        let actual: Vec<_> = findings(&issues, "python:S6546")
            .iter()
            .map(|issue| {
                let span = &issue.range;
                let row = source.lines().nth(span.start.line as usize - 1).unwrap();
                (
                    span.start.line,
                    &row[span.start.column as usize..span.end.column as usize],
                    issue.message.as_str(),
                )
            })
            .collect();
        let message = "Use a union type expression for this type hint.";
        assert_eq!(
            actual,
            vec![
                (3, "tuple[t.Union[int, str], U[int, bytes]]", message),
                (4, "U[int, str]", message),
                (4, "U[int, str]", message),
                (4, "(t.Union[int, str])", message),
                (5, "list[U[int, str]]", message),
            ],
        );
    }

    #[test]
    fn s6546_ignores_unknown_union_members_and_non_annotations() {
        let source = concat!(
            "from user_types import Union\n",
            "import user_types as typing\n",
            "from typing import Optional, Union as U\n",
            "marker: Union[int, str] = 1\n",
            "value: typing.Union[int, str] = 1\n",
            "maybe: Optional[int] = None\n",
            "literal: \"U[int, str]\" = 1\n",
            "alias = U[int, str]\n",
        );
        assert!(findings(&scan(source), "python:S6546").is_empty());
    }
}
