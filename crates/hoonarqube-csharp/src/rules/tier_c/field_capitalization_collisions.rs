use super::support::shadowed_field_sites;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4025 — child fields differing from a parent field only by
/// capitalization. Subset: direct file-local base classes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    shadowed_field_sites(root, source)
        .into_iter()
        .filter(|(derived, _, base)| derived != base && derived.eq_ignore_ascii_case(base))
        .map(|(_, node, _)| {
            issue(
                language,
                "S4025",
                "Rename this field; it differs from an inherited field only by capitalization.",
                range_of(node, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4025_ignores_derived_without_field_declarators() {
        let report = analyze_default(
            "class Base\n{\n    protected int count;\n}\nclass Derived : Base\n{\n    void Touch()\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4025").is_empty());
    }

    #[test]
    fn s4025_ignores_exact_name_shadowing() {
        let report = analyze_default(
            "class Base\n{\n    protected int Count;\n}\nclass Derived : Base\n{\n    private int Count;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4025").is_empty());
    }

    #[test]
    fn s4025_ignores_unresolvable_base_classes() {
        let report = analyze_default("class Repo : Exception\n{\n    private string message;\n}\n");
        assert!(with_key(&report, "csharpsquid:S4025").is_empty());
    }

    #[test]
    fn s4025_flags_each_collision_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    protected int count;\n    protected string name;\n}\nclass Derived : Base\n{\n    private int COUNT;\n    private string Name;\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S4025");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 8);
        assert_eq!(found[1].range.start.line, 9);
    }

    #[test]
    fn s4025_flags_nested_local_type_collisions() {
        let report = analyze_default(
            "class Outer\n{\n    class Base\n    {\n        protected int count;\n    }\n    class Inner : Base\n    {\n        private int Count;\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S4025");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 9);
    }
}
