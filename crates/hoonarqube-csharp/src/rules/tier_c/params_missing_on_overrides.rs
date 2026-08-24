use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3262 — overrides dropping the `params` modifier their base
/// declares at the same parameter position. Subset: direct file-local bases.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_units = parameter_units(overriding, source);
            for (index, base_unit) in parameter_units(base, source).iter().enumerate() {
                if base_unit.has_params {
                    match overriding_units.get(index) {
                        Some(unit) if !unit.has_params => {
                            return overriding.child_by_field_name("name");
                        }
                        _ => {}
                    }
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S3262",
                "Add 'params' to this override to match the base declaration.",
                range_of(name),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3262_minimal_derived_without_base_member_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n}\nclass Sub : Base\n{\n    public override void Show() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3262").is_empty());
    }

    #[test]
    fn s3262_params_dropped_on_a_later_position_alone_is_flagged() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead, params int[] tail) { }\n}\nclass Sub : Base\n{\n    public override void Send(int lead, int[] tail) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3262");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s3262_removing_the_whole_params_parameter_is_out_of_scope() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(params int[] xs) { }\n}\nclass Sub : Base\n{\n    public override void Send() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3262").is_empty());
    }

    #[test]
    fn s3262_params_kept_at_every_position_stays_clean() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(int lead, params int[] tail) { }\n}\nclass Sub : Base\n{\n    public override void Send(int lead, params int[] tail) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3262").is_empty());
    }

    #[test]
    fn s3262_hiding_without_override_modifier_never_pairs() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Send(params int[] xs) { }\n}\nclass Sub : Base\n{\n    public void Send(int[] xs) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3262").is_empty());
    }

    #[test]
    fn s3262_reports_each_dropping_override_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void First(params int[] xs) { }\n    public virtual void Second(params int[] ys) { }\n}\nclass Sub : Base\n{\n    public override void First(int[] xs) { }\n    public override void Second(int[] ys) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3262");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 9);
    }
}
