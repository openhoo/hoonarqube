use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{MemberFlavor, UsageSymbols, is_private_member, owner_is_partial};
use hoonarqube_ir::Issue;

/// csharpsquid:S3459 — private fields that are read but never assigned.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.has_initializer
            || !symbols.writes_of(member.name).is_empty()
            || symbols.uses_of(member.name).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3459",
            format!(
                "Remove unassigned field '{}', or set its value.",
                member.name
            ),
            range_of(member.anchor, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3459_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3459").is_empty());
    }

    #[test]
    fn s3459_flags_read_only_field_at_declaration_with_message() {
        let report = analyze_default(
            "class C\n{\n    private int cached;\n\n    public int Get()\n    {\n        return cached;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3459");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(
            flagged[0].message,
            "Remove unassigned field 'cached', or set its value."
        );
    }

    #[test]
    fn s3459_ignores_fields_that_receive_assignments() {
        let report = analyze_default(
            "class C\n{\n    private int cached;\n\n    public int Get()\n    {\n        cached = 42;\n        return cached;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3459").is_empty());
    }

    #[test]
    fn s3459_ignores_unused_initialized_attributed_and_public_fields() {
        let orphan = analyze_default("class C\n{\n    private int orphan;\n}\n");
        assert!(with_key(&orphan, "csharpsquid:S3459").is_empty());

        let initialized = analyze_default(
            "class C\n{\n    private int ready = 1;\n\n    public int Get()\n    {\n        return ready;\n    }\n}\n",
        );
        assert!(with_key(&initialized, "csharpsquid:S3459").is_empty());

        let attributed = analyze_default(
            "class C\n{\n    [System.Obsolete]\n    private int legacy;\n\n    public int Get()\n    {\n        return legacy;\n    }\n}\n",
        );
        assert!(with_key(&attributed, "csharpsquid:S3459").is_empty());

        let public_field = analyze_default(
            "class C\n{\n    public int exposed;\n\n    public int Get()\n    {\n        return exposed;\n    }\n}\n",
        );
        assert!(with_key(&public_field, "csharpsquid:S3459").is_empty());
    }

    #[test]
    fn s3459_reports_two_violations_at_distinct_lines() {
        let report = analyze_default(
            "class C\n{\n    private int first;\n    private int second;\n\n    public int Sum()\n    {\n        return first + second;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3459");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
    }
}
