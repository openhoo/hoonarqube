use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3600 — overrides introducing `params` where the base has
/// none at that position. Subset: direct file-local bases.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_units = parameter_units(overriding, source);
            let base_units = parameter_units(base, source);
            for (index, unit) in overriding_units.iter().enumerate() {
                if unit.has_params
                    && base_units
                        .get(index)
                        .is_some_and(|base_unit| !base_unit.has_params)
                {
                    return collect_kinds(overriding, &["params"]).first().copied();
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S3600",
                "'params' should be removed from this override.",
                range_of(name, source),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3600_minimal_derived_without_base_member_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n}\nclass Sub : Base\n{\n    public override void Show() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3600").is_empty());
    }

    #[test]
    fn s3600_params_introduced_on_a_later_position_alone_is_flagged() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead, int tail) { }\n}\nclass Sub : Base\n{\n    public override void Send(int lead, params int[] rest) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3600");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s3600_params_kept_at_every_matching_position_stays_clean() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead, params int[] tail) { }\n}\nclass Sub : Base\n{\n    public override void Send(int lead, params int[] tail) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3600").is_empty());
    }

    #[test]
    fn s3600_extension_beyond_base_arity_is_out_of_scope() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead) { }\n}\nclass Sub : Base\n{\n    public override void Send(int lead, params int[] more) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3600").is_empty());
    }

    #[test]
    fn s3600_hiding_without_override_modifier_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead) { }\n}\nclass Sub : Base\n{\n    public void Send(params int[] rest) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3600").is_empty());
    }

    #[test]
    fn s3600_reports_each_introducing_override_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void First(int a) { }\n    public virtual void Second(int b) { }\n}\nclass Sub : Base\n{\n    public override void First(params int[] xs) { }\n    public override void Second(params int[] ys) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3600");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 9);
    }
}
