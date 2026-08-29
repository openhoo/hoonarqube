use super::support::attribute_named;
use super::support::has_attribute;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3450 — `[DefaultParameterValue]` only takes effect together
/// with `[Optional]`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        let attributes = attributes_of(parameter, source);
        if has_attribute(&attributes, "DefaultParameterValue")
            && !has_attribute(&attributes, "Optional")
        {
            let default_attribute =
                attribute_named(parameter, source, "DefaultParameterValue").unwrap_or(parameter);
            issues.push(issue(
                language,
                "S3450",
                "Add the 'Optional' attribute to this parameter.",
                range_of(default_attribute, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3450_anchors_qualified_default_parameter_value_attribute() {
        let report = analyze_default(
            "class C\n{\n    void M([System.Runtime.InteropServices.DefaultParameterValue(1)] int value) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3450");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.column, 12);
        assert!(flagged[0].range.end.column < 70);
    }
}
