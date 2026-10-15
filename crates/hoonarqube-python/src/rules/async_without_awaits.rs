use crate::engine::file_context::FileContext;
use crate::support::child_exprs;
use crate::support::flow_location;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

pub(crate) fn check_async_without_awaits(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt
            && function.is_async
            && !is_exempt_async_function(function, &file_ctx.classes)
            && !async_features_present(function)
        {
            let mut issue = issue_at(
                "python:S7503",
                "Use asynchronous features in this function or remove the `async` keyword.",
                function.name.range(),
                index,
                source,
            );
            if let Some(range) = async_keyword_range(function, source) {
                issue = issue.with_flow(vec![flow_location(
                    "This function is async.",
                    range,
                    index,
                    source,
                )]);
            }
            issues.push(issue);
        }
    }
    issues
}

/// The locked parser starts an undecorated async declaration at its keyword.
/// Recovered or inconsistent ranges must not invent a supporting location.
fn async_keyword_range(
    function: &ruff_python_ast::StmtFunctionDef,
    source: &str,
) -> Option<TextRange> {
    let declaration = function.range();
    let name = function.name.range();
    let start = declaration.start();
    let end = start.checked_add(TextSize::new(5))?;
    source.get(start.to_usize()..declaration.end().to_usize())?;
    if end > declaration.end()
        || name.is_empty()
        || end > name.start()
        || name.end() > declaration.end()
        || source.get(name.start().to_usize()..name.end().to_usize())
            != Some(function.name.as_str())
        || source.get(start.to_usize()..end.to_usize()) != Some("async")
    {
        return None;
    }
    Some(TextRange::new(start, end))
}

// --- python:S7503 — async function without async features ---------------------------

/// Exemptions mirrored from the reference: abstract or decorated functions,
/// dunder methods, trivial bodies (empty/`raise`/`return NotImplemented`),
/// and methods that might override a base-class method (the class has any
/// base or keyword argument, so the hierarchy is unresolved).
fn is_exempt_async_function(
    function: &ruff_python_ast::StmtFunctionDef,
    classes: &[&ruff_python_ast::StmtClassDef],
) -> bool {
    if !function.decorator_list.is_empty() || function.name.as_str().starts_with("__") {
        return true;
    }
    let trivial = function.body.iter().all(|stmt| match stmt {
        Stmt::Pass(_) | Stmt::Raise(_) => true,
        Stmt::Expr(expr) => matches!(
            expr.value.as_ref(),
            Expr::StringLiteral(_) | Expr::EllipsisLiteral(_)
        ),
        Stmt::Return(ret) => ret.value.as_deref().is_some_and(
            |value| matches!(value, Expr::Name(name) if name.id.as_str() == "NotImplemented"),
        ),
        _ => false,
    });
    if trivial {
        return true;
    }
    // A method inside a class with any base or `metaclass=` may override a
    // synchronous base method.
    classes.iter().any(|class| {
        class
            .body
            .iter()
            .any(|member| matches!(member, Stmt::FunctionDef(m) if m.range() == function.range()))
            && class.arguments.as_deref().is_some_and(|arguments| {
                !arguments.args.is_empty() || !arguments.keywords.is_empty()
            })
    })
}

fn async_features_present(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    let mut found = false;
    for_each_stmt_in_scope(function.body.as_slice(), &mut |stmt| {
        match stmt {
            Stmt::For(loop_stmt) => found |= loop_stmt.is_async,
            Stmt::With(with_stmt) => found |= with_stmt.is_async,
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr_for_async_scope(expr, &mut |expr| {
                found |= matches!(expr, Expr::Await(_) | Expr::Yield(_));
                match expr {
                    Expr::ListComp(c) => found |= c.generators.iter().any(|g| g.is_async),
                    Expr::SetComp(c) => found |= c.generators.iter().any(|g| g.is_async),
                    Expr::DictComp(c) => found |= c.generators.iter().any(|g| g.is_async),
                    Expr::Generator(c) => found |= c.generators.iter().any(|g| g.is_async),
                    _ => {}
                }
            });
        }
    });
    found
}
fn for_each_expr_for_async_scope(expr: &Expr, visit: &mut impl FnMut(&Expr)) {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        visit(expr);
        let mut children = child_exprs(expr);
        if matches!(expr, Expr::Lambda(_)) {
            // A lambda body executes in its own function scope. Defaults and
            // annotations are still evaluated while creating the lambda.
            children.pop();
        }
        pending.extend(children.into_iter().rev());
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, issue, scan};
    use hoonarqube_ir::{FlowLocation, Pos, Range};

    use super::check_async_without_awaits;
    use crate::engine::file_context::FileContext;
    use ruff_python_ast::Stmt;
    use ruff_source_file::LineIndex;
    use ruff_text_size::TextRange;

    #[test]
    fn s7503_flags_async_functions_without_awaits() {
        let flagged = scan(concat!(
            "async def noop():\n",
            "    return 1\n",
            "async def real():\n",
            "    await asyncio.sleep(1)\n"
        ));
        let nested_lambda_yield = scan("async def outer():\n    return lambda: (yield 1)\n");
        assert_eq!(findings(&nested_lambda_yield, "python:S7503").len(), 1);
        let found = findings(&flagged, "python:S7503");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
        assert_eq!(
            *found[0],
            issue(
                "python:S7503",
                "Use asynchronous features in this function or remove the `async` keyword.",
                (1, 10),
                (1, 14),
            )
            .with_flow(vec![FlowLocation::in_primary_file(
                "This function is async.",
                Range {
                    start: Pos { line: 1, column: 0 },
                    end: Pos { line: 1, column: 5 },
                },
            )])
        );
    }
    #[test]
    fn s7503_preserves_async_generator_contracts() {
        let generator = scan("async def values():\n    yield 1\n");
        assert!(findings(&generator, "python:S7503").is_empty());
        let nested_yield =
            scan("async def outer():\n    def values():\n        yield 1\n    return values\n");
        assert_eq!(findings(&nested_yield, "python:S7503").len(), 1);
    }

    #[test]
    fn s7503_unproven_keyword_ranges_keep_the_original_primary() {
        let source = "async def noop():\n    return '𐐀'\n";
        let parsed = ruff_python_parser::parse_module(source).expect("valid fixture");
        let index = LineIndex::from_source_text(source);
        let end = u32::try_from(source.len()).expect("small fixture");
        let inside_unicode =
            u32::try_from(source.find('𐐀').expect("astral character") + 1).expect("small fixture");
        let cases = [
            (1, end, 10, 14),
            (0, 4, 10, 14),
            (0, 13, 10, 14),
            (0, end + 1, 10, 14),
            (0, end, 4, 8),
            (0, end, 10, 10),
            (0, end, 11, 15),
            (u32::MAX, u32::MAX, 10, 14),
            (0, inside_unicode, 10, 14),
        ];
        for (start, end, name_start, name_end) in cases {
            let mut stmt = parsed.syntax().body[0].clone();
            let Stmt::FunctionDef(function) = &mut stmt else {
                panic!("function fixture");
            };
            function.range = TextRange::new(start.into(), end.into());
            function.name.range = TextRange::new(name_start.into(), name_end.into());
            let mut context = FileContext::build(&parsed, source);
            context.stmts = vec![&stmt];
            assert_eq!(
                check_async_without_awaits(&index, source, &context),
                vec![issue(
                    "python:S7503",
                    "Use asynchronous features in this function or remove the `async` keyword.",
                    (1, name_start),
                    (1, name_end),
                )],
                "declaration {start}..{end}, name {name_start}..{name_end}"
            );
        }
    }
}
