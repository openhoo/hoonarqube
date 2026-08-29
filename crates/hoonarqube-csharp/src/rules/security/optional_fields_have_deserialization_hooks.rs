use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_any_attribute;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3926 — types with `[OptionalField]` state require both
/// deserialization lifecycle handlers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node)
            || !member_declarations_of_kind(type_node, "field_declaration")
                .iter()
                .any(|field| has_any_attribute(*field, source, &["OptionalField"]))
        {
            continue;
        }
        let methods = member_declarations_of_kind(type_node, "method_declaration");
        let has_before = methods
            .iter()
            .any(|method| has_any_attribute(*method, source, &["OnDeserializing"]));
        let has_after = methods
            .iter()
            .any(|method| has_any_attribute(*method, source, &["OnDeserialized"]));
        if has_before && has_after {
            continue;
        }
        let message = match (has_before, has_after) {
            (false, false) => "Add deserialization event handlers.",
            (false, true) => "Add the missing 'OnDeserializingAttribute' event handler.",
            (true, false) => "Add the missing 'OnDeserializedAttribute' event handler.",
            (true, true) => continue,
        };
        issues.push(issue(
            language,
            "S3926",
            message,
            range_of(
                type_node.child_by_field_name("name").unwrap_or(type_node),
                source,
            ),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3926_reports_once_per_type_with_both_handlers_missing() {
        let report = analyze_default(
            "[Serializable]\nclass Record\n{\n    [OptionalField] int revision;\n    [OptionalField] string note;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3926");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].message, "Add deserialization event handlers.");
    }

    #[test]
    fn s3926_requires_each_lifecycle_handler() {
        let before_only = analyze_default(
            "class Record\n{\n    [OptionalField] int revision;\n    [OnDeserializing] void Before(StreamingContext context) { }\n}\n",
        );
        assert_eq!(
            with_key(&before_only, "csharpsquid:S3926")[0].message,
            "Add the missing 'OnDeserializedAttribute' event handler."
        );

        let complete = analyze_default(
            "class Record\n{\n    [OptionalField] int revision;\n    [OnDeserializing] void Before(StreamingContext context) { }\n    [OnDeserialized] void After(StreamingContext context) { }\n}\n",
        );
        assert!(with_key(&complete, "csharpsquid:S3926").is_empty());
    }
}
