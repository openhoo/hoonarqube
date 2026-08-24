use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{base_call_name, enclosing_type};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3249 — types extending `object` directly gain nothing from
/// `base.Equals`/`base.GetHashCode`; those calls equal identity checks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let base_member = base_call_name(invocation, source);
        let relevant = matches!(base_member, Some("Equals" | "GetHashCode"));
        let object_derived =
            enclosing_type(invocation).is_some_and(|type_node| !has_base_list(type_node));
        if relevant && object_derived {
            issues.push(issue(
                language,
                "S3249",
                "Remove this redundant base call; the type extends 'object' directly.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// Whether a type declares a base list at all.
fn has_base_list(type_node: Node<'_>) -> bool {
    let mut cursor = type_node.walk();
    type_node
        .children(&mut cursor)
        .any(|child| child.kind() == "base_list")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3249_flags_base_equals_on_object_derived_types() {
        let report = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => base.Equals(obj);\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3249").len(), 1);
    }

    #[test]
    fn s3249_any_base_list_disarms_the_rule() {
        let report = analyze_default(
            "class C : System.IDisposable\n{\n    public void Dispose() { }\n\n    public override int GetHashCode()\n    {\n        return base.GetHashCode();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3249").is_empty());
    }
}
