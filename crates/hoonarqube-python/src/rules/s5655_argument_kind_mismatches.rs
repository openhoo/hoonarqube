use crate::engine::calls::LocalSignatures;
use crate::engine::calls::s5655_check_call;
use crate::engine::file_context::AnyImport;
use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::for_each_expr;
use crate::support::for_each_stmt_with_class;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5655 — arguments should be of an expected type -------------------

/// python:S5655 — flags literal arguments that provably contradict a simple
/// concrete parameter annotation of the resolved file-local callee, plus a
/// small table of typeshed-backed stdlib signatures the reference resolves.
pub(crate) fn check_s5655_argument_kind_mismatches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    signatures: &LocalSignatures,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let mut issues = Vec::new();
    for_each_stmt_with_class(module, None, &mut |stmt, class_context| {
        for top_expr in stmt_exprs(stmt) {
            for_each_expr(top_expr, &mut |expr| {
                let Expr::Call(call) = expr else {
                    return;
                };
                if let Some(resolved) = signatures.resolve(&call.func, class_context) {
                    s5655_check_call(&resolved, call, &mut issues, index, source);
                    return;
                }
                check_stdlib_signature(call, file_ctx, &mut issues, index, source);
            });
        }
    });
    issues
}

/// Typeshed signatures the reference resolves for stdlib calls: callee FQN,
/// positional index, and the literal kinds the parameter accepts. Only the
/// entries exercised by the oracle are listed; unknown callees stay silent.
const STDLIB_SIGNATURES: &[(&str, usize, &[&str])] = &[
    // email.utils.getaddresses(fieldvalues: list) — a tuple literal is not a
    // list, which is the divergence the oracle flagged.
    ("email.utils.getaddresses", 0, &["list"]),
];

fn check_stdlib_signature(
    call: &ruff_python_ast::ExprCall,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let Some(fqn) = callee_fqn(&call.func, file_ctx) else {
        return;
    };
    for &(name, position, accepted) in STDLIB_SIGNATURES {
        if fqn != name {
            continue;
        }
        let Some(argument) = call.arguments.args.get(position) else {
            continue;
        };
        let Some(kind) = typed_literal_kind(argument) else {
            continue;
        };
        if !accepted.contains(&kind) {
            issues.push(issue_at(
                "python:S5655",
                &format!("Change this argument; Function \"{name}\" expects a different type"),
                argument.range(),
                index,
                source,
            ));
        }
    }
}

/// Fully qualified callee path: `from module import name` resolution for
/// bare names first (the import binds the FQN), then `dotted_name` for
/// attribute paths.
fn callee_fqn(func: &Expr, file_ctx: &FileContext) -> Option<String> {
    if let Expr::Name(name) = func {
        for import in &file_ctx.imports {
            let AnyImport::From(from) = import else {
                continue;
            };
            let Some(module) = from.module.as_deref() else {
                continue;
            };
            if let Some(alias) = from.names.iter().find(|alias| {
                alias.asname.as_deref().unwrap_or(alias.name.as_str()) == name.id.as_str()
            }) {
                return Some(format!("{module}.{}", alias.name));
            }
        }
    }
    dotted_name(func)
}
