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
        let label = match call.func.as_ref() {
            Expr::Attribute(attribute) => format!("str.{}", attribute.attr),
            _ => called_name(&call.func).unwrap_or_default().to_string(),
        };
        issues.push(issue_at(
            "python:S2201",
            &format!("The return value of \"{label}\" must be used."),
            call.func.range(),
            index,
            source,
        ));
    }
    issues
}

// --- python:S2201 — return values from pure calls should not be ignored ------

// Sonar's IgnoredPureOperationsCheck free-function allowlist — `len`,
// `hash`, `chr` are NOT in it; `type`, `set`, `dict`, `min`, `max`, `sum`,
// `isinstance`, `super` are.
const PURE_FREE_FUNCTIONS: [&str; 44] = [
    "set",
    "dict",
    "frozenset",
    "str",
    "repr",
    "ascii",
    "ord",
    "hex",
    "oct",
    "bin",
    "bool",
    "bytes",
    "memoryview",
    "bytearray",
    "abs",
    "round",
    "min",
    "max",
    "divmod",
    "sum",
    "pow",
    "sorted",
    "filter",
    "enumerate",
    "reversed",
    "range",
    "slice",
    "zip",
    "help",
    "dir",
    "id",
    "object",
    "staticmethod",
    "classmethod",
    "property",
    "type",
    "isinstance",
    "issubclass",
    "callable",
    "format",
    "vars",
    "locals",
    "globals",
    "super",
];

const PURE_STRING_METHODS: [&str; 44] = [
    "upper",
    "lower",
    "capitalize",
    "casefold",
    "title",
    "swapcase",
    "strip",
    "lstrip",
    "rstrip",
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
    "format",
    "format_map",
    "translate",
    "expandtabs",
    "maketrans",
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

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    /// Issue #675: Sonar's `IgnoredPureOperationsCheck` allowlist contains
    /// `type` (plus `set`/`dict`/`min`/`max`/`sum`/`isinstance`/`super`)
    /// but NOT `len`/`hash`/`chr`. On the pinned campaign repro the bare
    /// `type(...)` call must fire while `hash`/`len` stay clean.
    #[test]
    fn s2201_matches_sonar_allowlist_on_campaign_repro() {
        let source = concat!(
            "def f(model, body_copy):\n",
            "    type(model._meta.object_name, model.__bases__, body_copy)\n",
            "    hash(body_copy)\n",
            "    len(body_copy)\n",
        );
        let report = scan(source);
        let found = findings(&report, "python:S2201");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "The return value of \"type\" must be used."
        );
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 4);
        assert_eq!(found[0].range.end.column, 8);
    }

    /// Every remaining Sonar-listed free function must fire; the invented
    /// entries (`chr`, `hash`, `len`) must not.
    #[test]
    fn s2201_flags_only_sonar_listed_pure_calls() {
        let flagged = concat!(
            "set(items)\n",
            "dict(pairs)\n",
            "min(values)\n",
            "max(values)\n",
            "sum(values)\n",
            "isinstance(item, Model)\n",
            "super()\n",
        );
        let report = scan(flagged);
        assert_eq!(findings(&report, "python:S2201").len(), 7);

        let clean = concat!("chr(code)\n", "hash(item)\n", "len(items)\n");
        let report = scan(clean);
        assert!(findings(&report, "python:S2201").is_empty());
    }
}
