use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    binary_operands, expression_name, integer_literal_value, operator_of,
};
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
                expression_name(target, source).is_some_and(|name| LIMIT_TARGETS.contains(&name))
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5693_requires_an_exact_limit_member_name() {
        let report = analyze_default(
            "class Options { long BackupMaxRequestBodySize; void Set() { BackupMaxRequestBodySize = 9000000; } }",
        );
        assert!(with_key(&report, "csharpsquid:S5693").is_empty());
    }
}
