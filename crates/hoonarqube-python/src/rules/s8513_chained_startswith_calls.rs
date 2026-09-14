use hoonarqube_ir::Issue;
use ruff_python_ast::{BoolOp, Expr, ExprBoolOp, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::string_literal_text;

const RULE_KEY: &str = "python:S8513";
const MESSAGE: &str =
    "Replace chained \"startswith\" calls with a single call using a tuple argument.";

/// python:S8513 — `value.startswith(a) or value.startswith(b)` with the
/// same receiver and fixed string prefixes is exactly
/// `value.startswith((a, b))`: one call, one tuple argument, identical
/// evaluation. The boolean-or expression anchors the finding. Mixed
/// methods, distinct receivers, non-literal prefixes, `and` chains, and
/// chains with an unrelated operand are not equivalent rewrites and
/// stay silent.
pub(crate) fn check_s8513_chained_startswith_calls(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |candidate| {
                if let Expr::BoolOp(bool_op) = candidate {
                    check_bool_op(bool_op, index, source, &mut issues);
                }
            });
        }
    });
    issues
}

fn check_bool_op(bool_op: &ExprBoolOp, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    if bool_op.op != BoolOp::Or {
        return;
    }
    let mut receivers = Vec::new();
    for value in &bool_op.values {
        match prefix_call_receiver(value, source) {
            Some(receiver) => receivers.push(receiver),
            None => return,
        }
    }
    let first = receivers[0];
    if receivers.iter().all(|receiver| *receiver == first) {
        issues.push(issue_at(RULE_KEY, MESSAGE, bool_op.range(), index, source));
    }
}

/// Textual receiver of a `receiver.startswith("literal")` call, or
/// `None` for any other expression shape.
fn prefix_call_receiver<'a>(expr: &'a Expr, source: &'a str) -> Option<&'a str> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let Expr::Attribute(method) = call.func.as_ref() else {
        return None;
    };
    if method.attr.as_str() != "startswith"
        || call.arguments.args.len() != 1
        || !call.arguments.keywords.is_empty()
    {
        return None;
    }
    string_literal_text(&call.arguments.args[0])?;
    Some(&source[method.value.range()])
}
