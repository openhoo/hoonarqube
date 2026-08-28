use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1006 — overrides changing a base method's default value.
/// Subset: positional comparison of parameters where BOTH sides spell out a
/// default; missing defaults on either side stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_parameters = parameter_units(overriding, source);
            let base_parameters = parameter_units(base, source);
            for (index, unit) in overriding_parameters.iter().enumerate() {
                let Some(base_unit) = base_parameters.get(index) else {
                    break;
                };
                if let (Some(value), Some(base_value)) =
                    (unit.default_value, base_unit.default_value)
                    && node_text(value, source) != node_text(base_value, source)
                {
                    return Some(value);
                }
            }
            None
        })
        .map(|value| {
            issue(
                language,
                "S1006",
                "Use the default parameter value defined in the overridden method.",
                range_of(value, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S1006";

    #[test]
    fn s1006_minimal_class_without_overrides_is_clean() {
        let report = analyze_default("class C {\n    void M(int x = 1) {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_matching_defaults_stay_clean() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 1) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_changed_default_value_flags_the_override_name() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }

    #[test]
    fn s1006_missing_default_on_either_side_is_uncovered() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_non_override_same_signature_is_ignored() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public new void M(int x = 2) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
