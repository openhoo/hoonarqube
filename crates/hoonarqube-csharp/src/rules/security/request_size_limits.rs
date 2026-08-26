use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, integer_literal_value, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5693 — request bodies beyond the tolerated size exhaust
/// server memory.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Catalog default `fileUploadSizeLimit` for csharpsquid:S5693.
    const REQUEST_BODY_LIMIT_BYTES: u64 = 8_388_608;
    const LIMIT_TARGETS: [&str; 4] = [
        "MaxRequestBodySize",
        "MaxRequestBodyLength",
        "MultipartBodyLengthLimit",
        "FormSize",
    ];
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                LIMIT_TARGETS
                    .iter()
                    .any(|limit| node_text(target, source).ends_with(limit))
                    && value.kind() == "integer_literal"
                    && integer_literal_value(node_text(value, source))
                        .is_some_and(|bytes| bytes > REQUEST_BODY_LIMIT_BYTES)
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S5693",
                format!("Keep request bodies at or below {REQUEST_BODY_LIMIT_BYTES} bytes."),
                range_of(assignment, source),
            )
        })
        .collect()
}
