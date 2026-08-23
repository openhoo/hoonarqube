use crate::support::LOAD_MODEL_TAILS;
use crate::support::called_name;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;
use std::collections::HashSet;

// --- python:S6982 — eval() after loading a model -------------------------------

pub(crate) fn check_missing_eval_after_load(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut loaded_models: HashSet<String> = HashSet::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func).is_some_and(|tail| LOAD_MODEL_TAILS.contains(&tail))
        {
            loaded_models.insert(target.id.as_str().to_string());
        }
    });
    let mut train_calls: Vec<(String, TextRange)> = Vec::new();
    let mut evaluated: HashSet<String> = HashSet::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            return;
        };
        let Expr::Name(receiver) = attribute.value.as_ref() else {
            return;
        };
        match attribute.attr.as_str() {
            "train" => train_calls.push((receiver.id.as_str().to_string(), expr.range())),
            "eval" => {
                evaluated.insert(receiver.id.as_str().to_string());
            }
            _ => {}
        }
    });
    let mut issues = Vec::new();
    for (receiver, range) in train_calls {
        if loaded_models.contains(&receiver) && !evaluated.contains(&receiver) {
            issues.push(issue_at(
                "python:S6982",
                "Call 'eval()' on this loaded model before inference; it stays in training mode.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}
