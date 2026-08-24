use super::support::declared_type_names;
use super::support::is_predefined_value_type_text;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::binary_operands;
use crate::rules::structure::binary_operator;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3610 — `==`/`!=` against `null` on operands whose declared
/// type text is a non-nullable value type. Subset: file-local declarations
/// only; values flowing through parameters of unanalyzed callers stay out.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NULL_COMPARISONS: [&str; 2] = ["==", "!="];
    let types = declared_type_names(root, source);
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|comparison| !is_error_tainted(*comparison))
        .filter(|comparison| NULL_COMPARISONS.contains(&binary_operator(*comparison, source)))
        .filter_map(|comparison| {
            let (left, right) = binary_operands(comparison)?;
            match (
                left.kind() == "null_literal",
                right.kind() == "null_literal",
            ) {
                (true, false) => Some(right),
                (false, true) => Some(left),
                _ => None,
            }
        })
        .filter(|operand| {
            operand.kind() == "identifier"
                && types
                    .get(node_text(*operand, source))
                    .is_some_and(|declared| is_predefined_value_type_text(declared))
        })
        .map(|operand| {
            issue(
                language,
                "S3610",
                "Remove this redundant comparison; this non-nullable value can never be 'null'.",
                range_of(operand),
            )
        })
        .collect()
}
