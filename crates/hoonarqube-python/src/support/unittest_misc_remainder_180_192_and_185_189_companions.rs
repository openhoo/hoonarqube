// --- Unittest/misc remainder (#180–#192) and #185–#189 companions.

use ruff_python_ast::Expr;

pub(crate) const COMPARISON_ASSERTS: [&str; 8] = [
    "assertEqual",
    "assertNotEqual",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
];

pub(crate) fn assertion_literal_kind(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::StringLiteral(_) => Some(0),
        Expr::BytesLiteral(_) => Some(1),
        Expr::BooleanLiteral(_) => Some(2),
        Expr::NumberLiteral(_) => Some(3),
        Expr::NoneLiteral(_) => Some(4),
        _ => None,
    }
}
