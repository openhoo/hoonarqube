use super::support::matched_method_pairs;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, node_text, parameters_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4015 — private methods on unsealed types must not hide a
/// public method with the same signature on a direct file-local base.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    matched_method_pairs(root, source, |modifiers| {
        has_modifier(modifiers, "private")
    })
        .into_iter()
        .filter_map(|(overriding, base)| {
            let owner = enclosing_type(overriding)?;
            if has_modifier(&modifiers_of(owner, source), "sealed")
                || !has_modifier(&modifiers_of(base, source), "public")
                || parameter_types(overriding, source) != parameter_types(base, source)
            {
                return None;
            }
            let name = overriding.child_by_field_name("name")?;
            let base_owner = enclosing_type(base)?
                .child_by_field_name("name")
                .map(|node| node_text(node, source))?;
            Some((name, base_owner, method_display(base, source)))
        })
        .map(|(name, base_owner, signature)| {
            issue(
                language,
                "S4015",
                format!(
                    "This member hides '{base_owner}.{signature}'. Make it non-private or seal the class."
                ),
                range_of(name, source),
            )
        })
        .collect()
}

fn parameter_types<'a>(method: Node<'_>, source: &'a str) -> Vec<&'a str> {
    parameters_of(method)
        .into_iter()
        .filter_map(|parameter| parameter.child_by_field_name("type"))
        .map(|type_node| node_text(type_node, source))
        .collect()
}

fn method_display(method: Node<'_>, source: &str) -> String {
    let name = method
        .child_by_field_name("name")
        .map_or("", |node| node_text(node, source));
    format!("{name}({})", parameter_types(method, source).join(", "))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S4015";

    #[test]
    fn s4015_minimal_class_without_overrides_is_clean() {
        let report = analyze_default("class C {\n    public void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4015_private_method_hiding_public_base_member_flags() {
        let report = analyze_default(
            "class B {\n    public void M() {\n    }\n}\nclass D : B {\n    private void M() {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }

    #[test]
    fn s4015_public_hiding_method_stays_clean() {
        let report = analyze_default(
            "class B {\n    public virtual void M() {\n    }\n}\nclass D : B {\n    public override void M() {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4015_widening_internal_to_public_is_clean() {
        let report = analyze_default(
            "class B {\n    internal virtual void M() {\n    }\n}\nclass D : B {\n    public override void M() {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4015_undeclared_contextual_modifiers_are_untouched() {
        let report = analyze_default(
            "class B {\n    virtual void M() {\n    }\n}\nclass D : B {\n    override void M() {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4015_sealed_derived_type_is_exempt() {
        let report = analyze_default(
            "class B {\n    public void M() {\n    }\n}\nsealed class D : B {\n    private void M() {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
