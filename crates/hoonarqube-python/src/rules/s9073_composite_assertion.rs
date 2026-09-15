use hoonarqube_ir::Issue;
use ruff_python_ast::{BoolOp, Expr, ModModule, Stmt, UnaryOp};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::for_each_stmt;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S9073";
const MESSAGE: &str = "Split this composite assertion into separate assertions.";

/// python:S9073 — an assertion joining independent facts: an `and` chain
/// hides which operand failed, and `assert not (a or b)` is its De Morgan
/// equivalent. Plain `assert a or b` stays silent because splitting it
/// would change the meaning from "at least one holds" to "all hold"; the
/// same exclusion covers a top-level `or` with a nested `and`. The assert
/// statement anchors the finding. Catalog scope MAIN: test-scoped files are
/// silenced centrally by the analyzer's MAIN-scope gate.
pub(crate) fn check_s9073_composite_assertion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Assert(assert) = stmt else {
            return;
        };
        let composite = match assert.test.as_ref() {
            Expr::BoolOp(bool_op) => bool_op.op == BoolOp::And,
            Expr::UnaryOp(unary_op) => {
                unary_op.op == UnaryOp::Not
                    && matches!(
                        unary_op.operand.as_ref(),
                        Expr::BoolOp(operand) if operand.op == BoolOp::Or
                    )
            }
            _ => false,
        };
        if composite {
            issues.push(issue_at(RULE_KEY, MESSAGE, assert.range(), index, source));
        }
    });
    issues
}
