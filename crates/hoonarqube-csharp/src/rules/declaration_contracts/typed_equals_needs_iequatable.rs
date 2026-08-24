use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of,
};
use crate::rules::expressions::{enclosing_type, first_named_child};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3897 — declaring a typed `Equals(T)` overload promises
/// `IEquatable<T>`; spell it out on the type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || has_modifier(&modifiers_of(method, source), "override")
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "Equals")
        {
            continue;
        }
        let parameters = parameters_of(method);
        if parameters.len() != 1 {
            continue;
        }
        let parameter_type =
            first_named_child(parameters[0]).map_or("", |type_node| node_text(type_node, source));
        if parameter_type.is_empty() || parameter_type == "object" {
            continue;
        }
        let implements = enclosing_type(method).is_none_or(|type_node| {
            base_simple_names(type_node, source)
                .iter()
                .any(|base| base.starts_with("IEquatable"))
        });
        if !implements {
            issues.push(issue(
                language,
                "S3897",
                "Declare 'IEquatable<T>' on this type.",
                range_of(method),
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3897_flags_typed_equals_without_the_interface() {
        let report = analyze_default("class C\n{\n    public bool Equals(C other) => true;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S3897").len(), 1);
    }

    #[test]
    fn s3897_accepts_declared_iequatable_bases() {
        let direct = analyze_default(
            "class C : IEquatable<C>\n{\n    public bool Equals(C other) => true;\n}\n",
        );
        assert!(with_key(&direct, "csharpsquid:S3897").is_empty());

        let qualified = analyze_default(
            "class C : System.IEquatable<C>\n{\n    public bool Equals(C other) => true;\n}\n",
        );
        assert!(with_key(&qualified, "csharpsquid:S3897").is_empty());
    }

    #[test]
    fn s3897_spares_object_signatures_and_overrides() {
        let overridden = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => true;\n}\n",
        );
        assert!(with_key(&overridden, "csharpsquid:S3897").is_empty());

        let object_parameter =
            analyze_default("class C\n{\n    public bool Equals(object obj) => true;\n}\n");
        assert!(with_key(&object_parameter, "csharpsquid:S3897").is_empty());

        let two_params =
            analyze_default("class C\n{\n    public bool Equals(C x, C y) => true;\n}\n");
        assert!(with_key(&two_params, "csharpsquid:S3897").is_empty());
    }

    #[test]
    fn s3897_reports_each_typed_overload() {
        let report = analyze_default(
            "struct V\n{\n    public bool Equals(V other) => true;\n\n    public bool Equals(int scalar) => true;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3897").len(), 2);
    }
}
