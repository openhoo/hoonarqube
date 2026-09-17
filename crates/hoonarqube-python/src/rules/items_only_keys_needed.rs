use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::stmts_load_any_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7512 — items() when only keys are needed -------------------------------

pub(crate) fn check_items_only_keys_needed(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::For(for_stmt) = stmt else { continue };
        let Expr::Tuple(tuple) = for_stmt.target.as_ref() else {
            continue;
        };
        let [Expr::Name(_), Expr::Name(value)] = &tuple.elts[..] else {
            continue;
        };
        let items_call = matches!(
            for_stmt.iter.as_ref(),
            Expr::Call(call) if matches!(call.func.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "items")
        );
        if !items_call {
            continue;
        }
        // The reference requires a provable dict receiver (dictItemsTypeCheck);
        // syntactic `.items()` on an unknown receiver is not enough.
        let Expr::Call(call) = for_stmt.iter.as_ref() else {
            continue;
        };
        let Expr::Attribute(attribute) = call.func.as_ref() else {
            continue;
        };
        if !receiver_is_known_dict(&attribute.value, file_ctx) {
            continue;
        }
        if !stmts_load_any_name(&for_stmt.body, &[value.id.to_string()]) {
            issues.push(issue_at(
                "python:S7512",
                "Iterate over the dictionary directly; the value is not used.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Whether the `.items()` receiver provably holds a dict: a dict literal, a
/// `dict(...)` call, or a name whose single assignment in the file is one of
/// those. Attribute receivers and unresolvable names are not provable.
fn receiver_is_known_dict(receiver: &Expr, file_ctx: &FileContext) -> bool {
    let name = match receiver {
        Expr::Dict(_) => return true,
        Expr::Call(call) => {
            return matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "dict");
        }
        Expr::Name(name) => name.id.as_str(),
        _ => return false,
    };
    let mut found: Option<&Expr> = None;
    for stmt in &file_ctx.stmts {
        let Stmt::Assign(assign) = stmt else {
            continue;
        };
        let [Expr::Name(target)] = assign.targets.as_slice() else {
            continue;
        };
        if target.id.as_str() != name {
            continue;
        }
        if found.is_some() {
            return false;
        }
        found = Some(assign.value.as_ref());
    }
    matches!(found, Some(Expr::Dict(_)))
        || matches!(found, Some(Expr::Call(call)) if matches!(call.func.as_ref(), Expr::Name(n) if n.id.as_str() == "dict"))
}
