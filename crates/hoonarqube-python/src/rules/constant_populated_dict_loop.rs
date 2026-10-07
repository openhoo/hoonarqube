use crate::engine::file_context::FileContext;
use crate::engine::scope::ScopeKind;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7519 — constant-populated dict built in a loop ------------------------

pub(crate) fn check_constant_populated_dict_loop(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    // A dict comprehension whose value is the same constant for every key
    // is the same pattern the reference flags for the loop form.
    for expr in &file_ctx.exprs {
        let Expr::DictComp(comp) = expr else {
            continue;
        };
        if !matches!(comp.key.as_deref(), Some(Expr::Name(_)))
            || comp.generators.len() != 1
            || !comp.generators[0].ifs.is_empty()
        {
            continue;
        }
        let shared_value = match comp.value.as_ref() {
            Expr::NoneLiteral(_)
            | Expr::NumberLiteral(_)
            | Expr::BooleanLiteral(_)
            | Expr::StringLiteral(_) => true,
            Expr::Name(name) => file_ctx
                .symbol_table()
                .resolved_loads
                .iter()
                .find(|load| load.range == name.range())
                .is_some_and(|load| {
                    load.target.is_none_or(|target| {
                        file_ctx.symbol_table().scopes[target].kind != ScopeKind::Comprehension
                    })
                }),
            _ => false,
        };
        if shared_value {
            issues.push(issue_at(
                "python:S7519",
                "Replace with dict fromkeys method call",
                comp.range(),
                index,
                source,
            ));
        }
    }
    issues
}
