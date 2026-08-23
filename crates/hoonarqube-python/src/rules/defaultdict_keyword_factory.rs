use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7507 — defaultdict default_factory keyword --------------------------

pub(crate) fn check_defaultdict_keyword_factory(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) != Some("defaultdict") {
            return;
        }
        for keyword in &call.arguments.keywords {
            if keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "default_factory")
            {
                issues.push(issue_at(
                    "python:S7507",
                    "Pass the default factory positionally; 'default_factory' is not a valid keyword.",
                    keyword.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
