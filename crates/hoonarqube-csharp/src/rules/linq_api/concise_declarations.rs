use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3257 — when the initializer spells out the type again, `var`
/// keeps the declaration honest without repeating it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["array_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        let text = node_text(creation, source);
        let Some(after_new) = text.strip_prefix("new ") else {
            continue;
        };
        let Some(bracket) = after_new.find("[]") else {
            continue;
        };
        if !after_new[bracket + 2..].contains('{') {
            continue;
        }
        let start = creation.start_byte() + 4;
        issues.push(issue(
            language,
            "S3257",
            "Remove the array type; it is redundant.",
            range_from_byte_offsets(start, start + bracket, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3257_interface_typed_declarations_stay_clean() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        System.Collections.Generic.IEnumerable<int> wide = new System.Collections.Generic.List<int>();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3257").is_empty());
    }

    #[test]
    fn s3257_does_not_prefer_var_for_object_creation() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        List<int> left = new List<int>(), right = new List<int>();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3257").is_empty());
    }

    #[test]
    fn s3257_flags_redundant_array_element_type() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var values = new int[] { 1, 2 };\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3257");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
