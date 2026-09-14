use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

use crate::support::dotted_name_is;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S9000";
const MESSAGE: &str =
    "Prefer the context manager form: wrap the raising code in \"with pytest.raises(...)\".";

/// python:S9000 — a `pytest.raises` call the test never enters: the
/// bare `pytest.raises(ValueError)` statement constructs and discards
/// the context manager, the deprecated callable-passing form
/// `pytest.raises(E, f, *args, **kwargs)` predates `with`, and the
/// typo `pytest.raises(E, f(*args))` runs the callable before the
/// manager is entered. Calls inside a `with` item's context
/// expression — including conditional and tuple forms — are the
/// context-manager use. The call anchors the finding.
pub(crate) fn check_s9000_raises_context_manager(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    if !is_pytest_file_name(path) {
        return Vec::new();
    }
    let body = parsed.syntax().body.as_slice();
    let entered = entered_raises_starts(body);
    let mut issues = Vec::new();
    for_each_stmt_expr(body, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        if !dotted_name_is(&call.func, "pytest.raises") {
            return;
        }
        if entered.contains(&call.range().start()) {
            return;
        }
        issues.push(issue_at(RULE_KEY, MESSAGE, call.range(), index, source));
    });
    issues
}

/// Start offsets of the `pytest.raises` calls a `with` statement
/// enters: any such call inside an item's context expression.
fn entered_raises_starts(body: &[Stmt]) -> Vec<TextSize> {
    let mut entered = Vec::new();
    for_each_stmt(body, &mut |stmt| {
        let Stmt::With(with_stmt) = stmt else {
            return;
        };
        for item in &with_stmt.items {
            for_each_expr(&item.context_expr, &mut |expr| {
                if let Expr::Call(call) = expr
                    && dotted_name_is(&call.func, "pytest.raises")
                {
                    entered.push(call.range().start());
                }
            });
        }
    });
    entered
}
