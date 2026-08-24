use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3449 — shift operators whose right operand is a literal that
/// can never be an integer. Subset: literal right operands (real/string/
/// bool/null); identifiers and computed operands need typing and stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const SHIFT_OPERATORS: [&str; 3] = ["<<", ">>", ">>>"];
    const NON_INTEGER_LITERALS: [&str; 4] = [
        "real_literal",
        "string_literal",
        "boolean_literal",
        "null_literal",
    ];
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|shift| !is_error_tainted(*shift))
        .filter(|shift| SHIFT_OPERATORS.contains(&binary_operator(*shift, source)))
        .filter(|shift| {
            binary_operands(*shift)
                .is_some_and(|(_, right)| NON_INTEGER_LITERALS.contains(&right.kind()))
        })
        .map(|shift| {
            issue(
                language,
                "S3449",
                "Use an integer as the right operand of this shift.",
                range_of(shift),
            )
        })
        .collect()
}
