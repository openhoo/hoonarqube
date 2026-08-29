use super::support::{member_uses, member_writes};
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, is_matching_constructor_write, is_private_member,
    is_ref_or_out_argument, owner_is_partial,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S2933 — private fields written only from constructors can
/// carry the `readonly` promise.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers, "readonly")
            || has_modifier(&modifiers, "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let writes = member_writes(symbols, member, source);
        if writes.is_empty() && !member.has_initializer {
            continue;
        }
        if member_uses(symbols, member, source)
            .iter()
            .any(|use_site| is_ref_or_out_argument(*use_site, source))
        {
            continue;
        }
        let field_is_static = has_modifier(&modifiers, "static");
        if writes
            .iter()
            .all(|write| is_matching_constructor_write(*write, field_is_static, source))
        {
            issues.push(issue(
                language,
                "S2933",
                format!("Make '{}' 'readonly'.", member.name),
                range_of(member.anchor, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2933_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2933").is_empty());
    }

    #[test]
    fn s2933_flags_constructor_written_field_with_message() {
        let report = analyze_default(
            "class C\n{\n    private int stamp;\n\n    public C()\n    {\n        stamp = 1;\n    }\n\n    public int Value\n    {\n        get { return stamp; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2933");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[0].message, "Make 'stamp' 'readonly'.");
    }

    #[test]
    fn s2933_ignores_already_readonly_and_public_fields() {
        let readonly = analyze_default(
            "class C\n{\n    private readonly int pinned = 1;\n\n    public int Value\n    {\n        get { return pinned; }\n    }\n}\n",
        );
        assert!(with_key(&readonly, "csharpsquid:S2933").is_empty());

        let public_field = analyze_default(
            "class C\n{\n    public int stamp;\n\n    public C()\n    {\n        stamp = 1;\n    }\n\n    public int Value\n    {\n        get { return stamp; }\n    }\n}\n",
        );
        assert!(with_key(&public_field, "csharpsquid:S2933").is_empty());
    }

    #[test]
    fn s2933_honors_ref_argument_escape_hatch() {
        let report = analyze_default(
            "class C\n{\n    private int stamp;\n\n    public C()\n    {\n        stamp = 1;\n    }\n\n    public void Refresh()\n    {\n        Bump(ref stamp);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2933").is_empty());
    }

    #[test]
    fn s2933_accepts_static_constructor_writes_for_static_fields() {
        let report = analyze_default(
            "class C\n{\n    private static int counter;\n\n    static C()\n    {\n        counter = 42;\n    }\n\n    public int Value()\n    {\n        return counter;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2933");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2933_does_not_borrow_writes_from_unrelated_types() {
        let report = analyze_default(
            "class A\n{\n    private int value;\n    public A() { value = 1; }\n}\n\nclass B\n{\n    private int value;\n    public void Set() { value = 2; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2933");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }
}
