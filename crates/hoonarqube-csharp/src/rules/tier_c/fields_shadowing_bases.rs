use super::support::shadowed_field_sites;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2387 — child fields hiding a same-named parent field.
/// Subset: exact-name collisions against a direct file-local base class.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    shadowed_field_sites(root, source)
        .into_iter()
        .filter(|(derived, _, base)| derived == base)
        .map(|(_, node, _)| {
            issue(
                language,
                "S2387",
                "Rename this field; it hides the field declared in its base class.",
                range_of(node),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2387_ignores_derived_without_fields() {
        let report = analyze_default(
            "class Base\n{\n}\nclass Derived : Base\n{\n    void Touch()\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2387").is_empty());
    }

    #[test]
    fn s2387_ignores_case_only_differences() {
        let report = analyze_default(
            "class Base\n{\n    protected int count;\n}\nclass Derived : Base\n{\n    private int COUNT;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2387").is_empty());
    }

    #[test]
    fn s2387_ignores_external_base_classes() {
        let report = analyze_default("class Repo : Exception\n{\n    private string Message;\n}\n");
        assert!(with_key(&report, "csharpsquid:S2387").is_empty());
    }

    #[test]
    fn s2387_flags_each_shadow_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    public int Id;\n    public string Tag;\n}\nclass Derived : Base\n{\n    public int Id;\n    public string Tag;\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2387");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 8);
        assert_eq!(found[1].range.start.line, 9);
    }

    #[test]
    fn s2387_flags_static_shadow_with_initializer() {
        let report = analyze_default(
            "class Config\n{\n    protected int Timeout;\n}\nclass Service : Config\n{\n    private static int Timeout = 30;\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2387");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 7);
    }

    #[test]
    fn s2387_flags_nested_local_type_shadows() {
        let report = analyze_default(
            "class Host\n{\n    class Seed\n    {\n        internal bool Flag;\n    }\n    class Sprout : Seed\n    {\n        internal bool Flag;\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S2387");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 9);
    }
}
