// --- style shapes (S6353, S6396, S6397, S5869, S5868, S5843, S5857)

use crate::support::{
    called_name, dotted_name, for_each_stmt_expr, is_false_literal, keyword_value,
};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

pub(crate) const CLASS_METACHARACTERS: [char; 15] = [
    '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}', '-',
];

const GRAPHEME_RANGES: [(char, char); 6] = [
    ('\u{0300}', '\u{036F}'),
    ('\u{200D}', '\u{200D}'),
    ('\u{FE00}', '\u{FE0F}'),
    ('\u{20D0}', '\u{20FF}'),
    ('\u{1AB0}', '\u{1AFF}'),
    ('\u{1F1E6}', '\u{1F1FF}'),
];

pub(crate) fn is_grapheme_codepoint(ch: char) -> bool {
    GRAPHEME_RANGES
        .iter()
        .any(|(low, high)| *low <= ch && ch <= *high)
}

pub(crate) fn is_regional_indicator(ch: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&ch)
}

// ---------------------------------------------------------------------------
// Tier C — feasible-heuristic security-sensitive rules.
//
// Every finding below is a true positive by construction: detection rests on
// API name tables, literal argument shapes, or structural patterns confined
// to the analyzed file. Framework-specific subsets are documented per rule.
// ---------------------------------------------------------------------------

/// Last-segment callee match (`a.b(...)` matches `"b"`).
pub(crate) fn is_call_method(call: &ruff_python_ast::ExprCall, method: &str) -> bool {
    called_name(&call.func) == Some(method)
}

/// Exact dotted-path callee match (`a.b.c(...)` matches `"a.b.c"`).
pub(crate) fn is_call_path(call: &ruff_python_ast::ExprCall, path: &str) -> bool {
    dotted_name(&call.func).is_some_and(|p| p == path)
}

/// Dotted-path match against exact entries or prefix families (import-style
/// tolerance: `from Crypto.Cipher import AES; AES.new(k)` resolves through
/// the leading-segment table instead of the full path).
pub(crate) fn call_path_matches(
    call: &ruff_python_ast::ExprCall,
    exact: &[&str],
    prefixes: &[&str],
    heads: &[&str],
) -> bool {
    dotted_name(&call.func).is_some_and(|p| {
        let path = p.as_str();
        exact.contains(&path)
            || prefixes.iter().any(|prefix| path.starts_with(prefix))
            || path
                .split('.')
                .next()
                .is_some_and(|head| heads.contains(&head))
    })
}

/// Loads of `<receiver>.<attr>` attribute expressions.
pub(crate) fn for_each_attr_load(
    stmts: &[Stmt],
    attr: &str,
    mut visit: impl FnMut(&ruff_python_ast::ExprAttribute),
) {
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::Attribute(candidate) = expr
            && candidate.attr.as_str() == attr
        {
            visit(candidate);
        }
    });
}

/// HTTP-client request methods whose TLS verification was disabled with the
/// `verify=False` keyword argument.
pub(crate) fn http_verify_disabled(call: &ruff_python_ast::ExprCall) -> bool {
    const HTTP_METHODS: [&str; 8] = [
        "get", "post", "put", "patch", "delete", "head", "options", "request",
    ];
    HTTP_METHODS.contains(&called_name(&call.func).unwrap_or_default())
        && keyword_value(&call.arguments, "verify").is_some_and(is_false_literal)
}
