use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    LOOP_KINDS, binary_operands, declares_string_local, expression_name, first_named_child,
    operator_of,
};
use crate::rules::modifiers::has_ancestor_with_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1643 — `+=` concatenation in a loop is quadratic; use a
/// `StringBuilder`. String evidence comes from a string-literal operand or a
/// `string`-typed left-hand local.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("+="))
        .filter(|assignment| has_ancestor_with_kind(*assignment, &LOOP_KINDS))
        .filter(|assignment| {
            let Some((left, right)) = binary_operands(*assignment) else {
                return false;
            };
            !collect_kinds(right, &["string_literal"]).is_empty()
                || left
                    .child_by_field_name("name")
                    .or_else(|| first_named_child(left))
                    .and_then(|identifier| expression_name(identifier, source))
                    .is_some_and(|name| declares_string_local(left, name, source))
        })
        .map(|assignment| {
            issue(
                language,
                "S1643",
                "Use a 'StringBuilder' instead of '+=' concatenation in this loop.",
                range_of(assignment),
            )
        })
        .collect()
}
