use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2612 — world/group-writable file modes -----------------------------

/// stat constants granting any "other" permission; the reference's
/// SENSITIVE_CONSTANTS list.
const SENSITIVE_CONSTANTS: [&str; 4] = [
    "stat.S_IRWXO",
    "stat.S_IROTH",
    "stat.S_IWOTH",
    "stat.S_IXOTH",
];

pub(crate) fn check_world_writable_modes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let path = dotted_name(&call.func);
        let bare = called_name(&call.func);
        let path_str = path.as_deref();
        // chmod family: mode is argument 1, safe when mode % 8 == 0.
        // os.umask: mask is argument 0, safe when mask % 8 == 7.
        let (position, safe_modulo) =
            if matches!(path_str, Some("os.chmod" | "os.fchmod" | "os.lchmod"))
                || matches!(bare, Some("chmod" | "fchmod" | "lchmod"))
            {
                (1usize, 0i64)
            } else if path_str == Some("os.umask") || bare == Some("umask") {
                (0usize, 7i64)
            } else {
                continue;
            };
        let Some(mode_expr) = call.arguments.args.get(position).or_else(|| {
            call.arguments
                .keywords
                .iter()
                .find(|keyword| keyword.arg.as_deref() == Some("mode"))
                .map(|keyword| &keyword.value)
        }) else {
            continue;
        };
        if is_unsafe_mode(mode_expr, safe_modulo, file_ctx, 0) {
            issues.push(issue_at(
                "python:S2612",
                "Make sure this permission is safe.",
                mode_expr.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Mirrors the reference's isUnsafeExpression: a sensitive stat constant, a
/// bitwise-or of unsafe operands, a numeric literal failing the modulo check,
/// or a name whose single assignment is unsafe.
fn is_unsafe_mode(expr: &Expr, safe_modulo: i64, file_ctx: &FileContext, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    if let Some(path) = dotted_name(expr)
        && SENSITIVE_CONSTANTS.contains(&path.as_str())
    {
        return true;
    }
    match expr {
        Expr::BinOp(binop) if matches!(binop.op, ruff_python_ast::Operator::BitOr) => {
            is_unsafe_mode(&binop.left, safe_modulo, file_ctx, depth + 1)
                || is_unsafe_mode(&binop.right, safe_modulo, file_ctx, depth + 1)
        }
        Expr::NumberLiteral(_) => {
            int_literal_value(expr).is_some_and(|value| value % 8 != safe_modulo)
        }
        Expr::Name(name) => single_assigned_expr(file_ctx, name.id.as_str())
            .is_some_and(|value| is_unsafe_mode(value, safe_modulo, file_ctx, depth + 1)),
        _ => false,
    }
}

/// The value of `name`'s only plain `name = value` assignment in the file.
fn single_assigned_expr<'a>(file_ctx: &'a FileContext<'a>, name: &str) -> Option<&'a Expr> {
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
            return None;
        }
        found = Some(assign.value.as_ref());
    }
    found
}
