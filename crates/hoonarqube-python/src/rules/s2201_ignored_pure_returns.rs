use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S2201 — bare-statement calls whose result is provably pure (the
/// static free-function allowlist, or a pure-`str`-method chain rooted at a
/// string literal) discard their return value.
pub(crate) fn check_s2201_ignored_pure_returns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Expr(expr_stmt) = stmt else {
            continue;
        };
        let Expr::Call(call) = expr_stmt.value.as_ref() else {
            continue;
        };
        let discarded = match call.func.as_ref() {
            Expr::Name(name) => PURE_FREE_FUNCTIONS.contains(&name.id.as_str()),
            Expr::Attribute(attribute) => {
                PURE_STRING_METHODS.contains(&attribute.attr.as_str())
                    && is_pure_string_expression(&attribute.value)
            }
            _ => false,
        };
        if !discarded {
            continue;
        }
        issues.push(issue_at(
            "python:S2201",
            &format!(
                "The return value of '{}' is not used.",
                called_name(&call.func).unwrap_or_default()
            ),
            call.range(),
            index,
            source,
        ));
    }
    issues
}

// --- python:S2201 — return values from pure calls should not be ignored ------

const PURE_FREE_FUNCTIONS: [&str; 13] = [
    "sorted", "reversed", "abs", "len", "repr", "ascii", "hash", "bin", "oct", "hex", "chr", "ord",
    "divmod",
];

const PURE_STRING_METHODS: [&str; 46] = [
    "upper",
    "lower",
    "capitalize",
    "casefold",
    "title",
    "swapcase",
    "strip",
    "lstrip",
    "rstrip",
    "removeprefix",
    "removesuffix",
    "replace",
    "center",
    "zfill",
    "ljust",
    "rjust",
    "count",
    "find",
    "rfind",
    "index",
    "rindex",
    "startswith",
    "endswith",
    "partition",
    "rpartition",
    "split",
    "rsplit",
    "splitlines",
    "join",
    "encode",
    "format",
    "format_map",
    "translate",
    "expandtabs",
    "isascii",
    "isalpha",
    "isalnum",
    "isdecimal",
    "isdigit",
    "isidentifier",
    "islower",
    "isnumeric",
    "isprintable",
    "isspace",
    "istitle",
    "isupper",
];

/// Whether the expression is a string literal or a call chain over pure
/// `str` methods rooted at a string literal (`"a,b".strip().split(",")`).
fn is_pure_string_expression(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) => true,
        Expr::Call(call) => matches!(
            call.func.as_ref(),
            Expr::Attribute(attribute)
                if PURE_STRING_METHODS.contains(&attribute.attr.as_str())
                    && is_pure_string_expression(&attribute.value)
        ),
        _ => false,
    }
}
