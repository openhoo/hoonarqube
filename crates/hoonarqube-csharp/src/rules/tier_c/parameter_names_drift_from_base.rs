use super::support::override_base_pairs;
use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S927 — overrides renaming parameters relative to the base
/// declaration. Subset: proper (non-flattened) positional parameters on
/// direct file-local bases; cross-file partial declarations stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let parameter_name = |parameter: &Node<'_>| -> Option<&str> {
        parameter
            .child_by_field_name("name")
            .map(|name| node_text(name, source))
    };
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_parameters = parameters_of(overriding);
            let base_parameters = parameters_of(base);
            if overriding_parameters.len() != base_parameters.len() {
                return None;
            }
            for (index, base_parameter) in base_parameters.iter().enumerate() {
                match (
                    parameter_name(&overriding_parameters[index]),
                    parameter_name(base_parameter),
                ) {
                    (Some(derived), Some(base)) if derived != base => {
                        return overriding.child_by_field_name("name");
                    }
                    _ => {}
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S927",
                "Rename this parameter to match the base declaration.",
                range_of(name, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s927_minimal_override_without_base_member_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n}\nclass Sub : Base\n{\n    public override void Show(int count)\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S927").is_empty());
    }

    #[test]
    fn s927_arity_mismatch_is_filtered_out() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Move(int left, int right) { }\n}\nclass Sub : Base\n{\n    public override void Move(int left) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S927").is_empty());
    }

    #[test]
    fn s927_case_only_parameter_drift_is_flagged() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Move(int distance) { }\n}\nclass Sub : Base\n{\n    public override void Move(int Distance) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S927");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s927_method_name_case_mismatch_prevents_pairing() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Move(int distance) { }\n}\nclass Sub : Base\n{\n    public override void MOVE(int meters) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S927").is_empty());
    }

    #[test]
    fn s927_static_vs_instance_hiding_without_override_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n    public static void Run(int speed) { }\n}\nclass Sub : Base\n{\n    public void Run(int velocity) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S927").is_empty());
    }

    #[test]
    fn s927_drift_on_a_later_position_alone_is_flagged_once() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Move(int x, int y) { }\n}\nclass Sub : Base\n{\n    public override void Move(int x, int yy) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S927");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s927_reports_each_drifting_override_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Walk(int stride) { }\n    public virtual void Run(int pace) { }\n}\nclass Sub : Base\n{\n    public override void Walk(int step) { }\n    public override void Run(int tempo) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S927");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s927_added_default_value_does_not_mask_drift() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Move(int distance) { }\n}\nclass Sub : Base\n{\n    public override void Move(int meters = 1) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S927");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }
}
