use std::collections::HashSet;

use crate::engine::file_context::{AnyImport, FileContext};
use crate::rules::logging_best_practices::LoggingFacts;
use crate::support::child_exprs;
use crate::support::dotted_name;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ExceptHandler, Expr, ExprCall, Stmt, UnaryOp};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

const RULE_KEY: &str = "python:S8572";
const MESSAGE: &str = "Use \"logging.exception()\" instead.";

/// python:S8572 — inside an `except` handler, `logging.error(...)` (or
/// `<logger>.error` / `<adapter>.error`) should be `logging.exception(...)`
/// so the traceback is captured. The reference only flags calls that log
/// exception information: a truthy `exc_info=` keyword, the handler's bound
/// exception name appearing in the arguments, or a
/// `traceback.format_exc()` call in the arguments. A falsy `exc_info=`
/// silences the call. The `error` attribute name anchors the finding, and
/// calls inside functions or lambdas nested in the handler are out of
/// scope. `SonarPython` scopes this rule to main sources.
pub(crate) fn check_logging_exception_in_handlers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = LoggingFacts::build(file_ctx);
    let format_exc_paths = format_exc_paths(file_ctx);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if attribute.attr.as_str() != "error" {
            continue;
        }
        if facts.logging_method(call).is_none() {
            continue;
        }
        let Some(handler) = enclosing_handler(call.range(), file_ctx) else {
            continue;
        };
        if nested_scope_contains(&handler.body, call.range()) {
            continue;
        }
        if !logs_exception_info(call, handler, &format_exc_paths) {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            attribute.attr.range,
            index,
            source,
        ));
    }
    issues
}

/// The innermost `except` handler whose body contains `range`.
fn enclosing_handler<'a>(
    range: TextRange,
    file_ctx: &FileContext<'a>,
) -> Option<&'a ruff_python_ast::ExceptHandlerExceptHandler> {
    let mut found = None;
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else {
            continue;
        };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(handler) = handler;
            let Some(first) = handler.body.first() else {
                continue;
            };
            let Some(last) = handler.body.last() else {
                continue;
            };
            let body = TextRange::new(first.range().start(), last.range().end());
            if body.contains_range(range) {
                found = Some(handler);
            }
        }
    }
    found
}

/// Whether `range` sits inside a function or lambda nested in the handler
/// body; the reference stops its handler search at those boundaries.
fn nested_scope_contains(body: &[Stmt], range: TextRange) -> bool {
    let mut nested = false;
    for_each_stmt(body, &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.range.contains_range(range)
        {
            nested = true;
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Lambda(lambda) = expr
                    && lambda.range.contains_range(range)
                {
                    nested = true;
                }
            });
        }
    });
    nested
}

/// Whether the call logs exception information: a truthy `exc_info=`
/// keyword, the handler's bound exception name in the arguments, or a
/// `traceback.format_exc()` call in the arguments.
fn logs_exception_info(
    call: &ExprCall,
    handler: &ruff_python_ast::ExceptHandlerExceptHandler,
    format_exc_paths: &HashSet<String>,
) -> bool {
    if let Some(exc_info) = call.arguments.find_keyword("exc_info") {
        return is_truthy_literal(&exc_info.value);
    }
    call.arguments
        .args
        .iter()
        .chain(call.arguments.keywords.iter().map(|keyword| &keyword.value))
        .any(|argument| argument_logs_exception(argument, handler, format_exc_paths))
}

/// Whether an argument tree mentions the bound exception name or calls
/// `traceback.format_exc()`, at any depth.
fn argument_logs_exception(
    argument: &Expr,
    handler: &ruff_python_ast::ExceptHandlerExceptHandler,
    format_exc_paths: &HashSet<String>,
) -> bool {
    let mut pending = vec![argument];
    while let Some(expr) = pending.pop() {
        if let Expr::Name(name) = expr
            && handler
                .name
                .as_ref()
                .is_some_and(|bound| bound.as_str() == name.id.as_str())
        {
            return true;
        }
        if let Expr::Call(call) = expr
            && format_exc_paths.contains(&dotted_name(&call.func).unwrap_or_default())
        {
            return true;
        }
        pending.extend(child_exprs(expr));
    }
    false
}

/// Local names that resolve to `traceback.format_exc`: the dotted path
/// itself plus every bound name imported from it.
fn format_exc_paths(file_ctx: &FileContext) -> HashSet<String> {
    let mut paths = HashSet::from(["traceback.format_exc".to_string()]);
    for entry in &file_ctx.imports {
        match entry {
            AnyImport::Plain(import) => {
                for alias in &import.names {
                    if alias.name.as_str() == "traceback" {
                        let bound = alias
                            .asname
                            .as_ref()
                            .map_or("traceback", |name| name.as_str());
                        paths.insert(format!("{bound}.format_exc"));
                    }
                }
            }
            AnyImport::From(import) => {
                if import.level != 0
                    || import
                        .module
                        .as_ref()
                        .is_none_or(|module| module.as_str() != "traceback")
                {
                    continue;
                }
                for alias in &import.names {
                    if alias.name.as_str() == "format_exc" {
                        let bound = alias
                            .asname
                            .as_ref()
                            .map_or("format_exc", |name| name.as_str());
                        paths.insert(bound.to_string());
                    }
                }
            }
        }
    }
    paths
}

/// Literal-level truthiness matching Sonar's `Expressions.isTruthy`.
fn is_truthy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::BooleanLiteral(literal) => literal.value,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() != Some(0),
            ruff_python_ast::Number::Float(value) => *value != 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real != 0.0 || *imag != 0.0,
        },
        Expr::StringLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::BytesLiteral(literal) => literal.value.iter().any(|part| !part.value.is_empty()),
        Expr::FString(_) | Expr::EllipsisLiteral(_) => true,
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        Expr::UnaryOp(unary) => {
            matches!(unary.op, UnaryOp::UAdd | UnaryOp::USub) && is_truthy_literal(&unary.operand)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, pos, scan, scan_test_file};
    use crate::{AnalyzerOptions, analyze};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8572")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8572_flags_sonar_noncompliant_example() {
        // Sonar's own Noncompliant example; the `error` attribute name
        // anchors the finding.
        let flagged = found(concat!(
            "import logging\n",
            "try:\n",
            "    raise ValueError(\"Invalid value\")\n",
            "except ValueError:\n",
            "    logging.error(\"Exception occurred\", exc_info=True)\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].message, "Use \"logging.exception()\" instead.");
        assert_eq!(flagged[0].range.start, pos(5, 12));
        assert_eq!(flagged[0].range.end, pos(5, 17));
    }

    #[test]
    fn s8572_flags_exception_name_and_format_exc_arguments() {
        let flagged = found(concat!(
            "import logging\n",
            "import traceback\n",
            "logger = logging.getLogger(__name__)\n",
            "try:\n",
            "    work()\n",
            "except ValueError as exc:\n",
            "    logger.error(\"failed: %s\", exc)\n",
            "    logging.error(traceback.format_exc())\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8572_stays_silent_on_compliant_and_unrelated_calls() {
        // Sonar's Compliant solution plus controls: no exception
        // information, falsy `exc_info`, calls outside handlers, and calls
        // inside functions nested in the handler.
        let clean = concat!(
            "import logging\n",
            "try:\n",
            "    raise ValueError(\"Invalid value\")\n",
            "except ValueError:\n",
            "    logging.exception(\"Exception occurred\")\n",
            "    logging.error(\"Exception occurred\")\n",
            "    logging.error(\"failed\", exc_info=False)\n",
            "    def report():\n",
            "        logging.error(\"failed\", exc_info=True)\n",
            "logging.error(\"failed\", exc_info=True)\n",
        );
        assert!(found(clean).is_empty());
    }

    #[test]
    fn s8572_stays_silent_on_test_scope_files() {
        // The rule's catalog scope is MAIN: test-scoped files drop the
        // finding entirely.
        let source = concat!(
            "import logging\n",
            "try:\n",
            "    work()\n",
            "except ValueError:\n",
            "    logging.error(\"failed\", exc_info=True)\n",
        );
        assert!(findings(&scan_test_file(source), "python:S8572").is_empty());
        let report = analyze(
            PathBuf::from("tests/test_handlers.py"),
            source,
            &AnalyzerOptions::default(),
        );
        assert!(findings(&report, "python:S8572").is_empty());
    }
}
