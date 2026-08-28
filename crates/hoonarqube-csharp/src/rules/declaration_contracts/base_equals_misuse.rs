use super::support::enclosing_method;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
};
use crate::rules::expressions::{base_call_name, enclosing_type};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3397 — calling `base.Equals` from within an `Equals` override
/// recurses into object identity semantics.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) || base_call_name(invocation, source) != Some("Equals") {
            continue;
        }
        let in_equals_override = enclosing_method(invocation).is_some_and(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Equals")
                && has_modifier(&modifiers_of(method, source), "override")
        });
        let owner_has_non_object_base = enclosing_type(invocation).is_some_and(|owner| {
            base_simple_names(owner, source)
                .into_iter()
                .any(|base| base != "object" && base != "Object")
        });
        if in_equals_override && owner_has_non_object_base {
            issues.push(issue(
                language,
                "S3397",
                "Change this guard condition to call 'object.ReferenceEquals'.",
                range_of(invocation, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3397_requires_the_enclosing_equals_override() {
        let report = analyze_default(
            "class C\n{\n    public override int GetHashCode()\n    {\n        return base.GetHashCode();\n    }\n\n    public bool Same(object obj)\n    {\n        return base.Equals(obj);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3397").is_empty());
    }

    #[test]
    fn s3397_flags_base_equals_in_multi_statement_overrides() {
        let report = analyze_default(
            "class Base\n{\n}\nclass C : Base\n{\n    public override bool Equals(object obj)\n    {\n        if (base.Equals(obj))\n        {\n            return true;\n        }\n        return false;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3397").len(), 1);
    }
}
