use crate::engine::file_context::FileContext;
use crate::support::{expr_normalized_text, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_wrapping_collection_constructors(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        let Expr::Name(callee) = call.func.as_ref() else {
            continue;
        };
        let name = callee.id.as_str();
        if file_ctx.load_map().contains_key(&callee.range()) {
            continue;
        }
        if call.arguments.keywords.is_empty()
            && let [only] = &call.arguments.args[..]
            && wrapping_redundancy(name, only)
            && comprehension_transforms(only, source)
        {
            let tuple_comprehension = name == "tuple"
                && matches!(
                    only,
                    Expr::ListComp(_) | Expr::SetComp(_) | Expr::DictComp(_)
                );
            let (message, range) = if tuple_comprehension {
                let kind = match only {
                    Expr::ListComp(_) => "list",
                    Expr::SetComp(_) => "set",
                    _ => "dict",
                };
                (
                    format!("Replace this {kind} comprehension by a generator."),
                    only.range(),
                )
            } else {
                (wrapping_message(name, only), call.func.range())
            };
            issues.push(issue_at("python:S7496", &message, range, index, source));
        }
    }
    issues
}

// --- python:S7496 — constructor wrapping an existing literal/comprehension ----

fn wrapping_redundancy(func_name: &str, argument: &Expr) -> bool {
    matches!(func_name, "list" | "set" | "dict" | "tuple")
        && matches!(
            argument,
            Expr::List(_)
                | Expr::Set(_)
                | Expr::Dict(_)
                | Expr::Tuple(_)
                | Expr::ListComp(_)
                | Expr::SetComp(_)
                | Expr::DictComp(_)
        )
        && (!matches!(argument, Expr::SetComp(_)) || matches!(func_name, "set" | "tuple"))
}

fn wrapping_message(func_name: &str, argument: &Expr) -> String {
    let same = matches!(
        (func_name, argument),
        ("list", Expr::List(_) | Expr::ListComp(_))
            | ("set", Expr::Set(_) | Expr::SetComp(_))
            | ("dict", Expr::Dict(_) | Expr::DictComp(_))
            | ("tuple", Expr::Tuple(_))
    );
    if same {
        format!("Remove the redundant {func_name} constructor call.")
    } else {
        format!("Replace this {func_name} constructor call by a {func_name} literal.")
    }
}

fn comprehension_transforms(argument: &Expr, source: &str) -> bool {
    let (element, generators) = match argument {
        Expr::ListComp(comp) => (Some(comp.elt.as_ref()), comp.generators.as_slice()),
        Expr::SetComp(comp) => (Some(comp.elt.as_ref()), comp.generators.as_slice()),
        _ => return true,
    };
    let [generator] = generators else { return true };
    element.is_none_or(|element| {
        expr_normalized_text(element, source) != expr_normalized_text(&generator.target, source)
    })
}
