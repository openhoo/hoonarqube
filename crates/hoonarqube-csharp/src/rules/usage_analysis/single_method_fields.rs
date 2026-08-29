use super::support::member_uses;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, TIER_B_MEMBER_KINDS, UsageSymbols, is_private_member, nearest_ancestor_of_kinds,
    owner_is_partial,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1450 — fields touched by exactly one method behave like
/// locals and belong in that method.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let uses = member_uses(symbols, member, source);
        if uses.is_empty() {
            continue;
        }
        let mut homes: Vec<Option<Node>> = uses
            .iter()
            .map(|use_site| nearest_ancestor_of_kinds(*use_site, &TIER_B_MEMBER_KINDS))
            .collect();
        homes.sort_by_key(|home| home.map(|owner| owner.byte_range().start));
        homes.dedup_by_key(|home| home.map(|owner| owner.byte_range().start));
        let single_method = matches!(homes.as_slice(), [Some(home)]
            if home.kind() == "method_declaration");
        if single_method {
            issues.push(issue(
                language,
                "S1450",
                format!(
                    "Remove the field '{}' and declare it as a local variable in the relevant methods.",
                    member.name
                ),
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
    fn s1450_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S1450").is_empty());
    }

    #[test]
    fn s1450_flags_single_method_field_at_declaration_with_message() {
        let report = analyze_default(
            "class C\n{\n    private int scratch;\n\n    public int Run()\n    {\n        scratch = 1;\n        return scratch;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1450");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(
            flagged[0].message,
            "Remove the field 'scratch' and declare it as a local variable in the relevant methods."
        );
    }

    #[test]
    fn s1450_ignores_fields_shared_with_accessors() {
        let report = analyze_default(
            "class C\n{\n    private int balance;\n\n    public int Balance\n    {\n        get { return balance; }\n    }\n\n    public void Add(int amount)\n    {\n        balance += amount;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1450").is_empty());
    }

    #[test]
    fn s1450_ignores_attributed_and_public_fields_used_in_one_method() {
        let attributed = analyze_default(
            "class C\n{\n    [System.Obsolete]\n    private int legacy;\n\n    public int Read()\n    {\n        return legacy;\n    }\n}\n",
        );
        assert!(with_key(&attributed, "csharpsquid:S1450").is_empty());

        let public_field = analyze_default(
            "class C\n{\n    public int shared;\n\n    public int Read()\n    {\n        return shared;\n    }\n}\n",
        );
        assert!(with_key(&public_field, "csharpsquid:S1450").is_empty());
    }

    #[test]
    fn s1450_requires_a_use_site() {
        let report = analyze_default(
            "class C\n{\n    private int orphan;\n\n    public void Touch()\n    {\n        Log(\"noop\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1450").is_empty());
    }

    #[test]
    fn s1450_does_not_borrow_method_homes_from_unrelated_types() {
        let report = analyze_default(
            "class A\n{\n    private int scratch;\n    public int Run() { scratch = 1; return scratch; }\n}\n\nclass B\n{\n    private int scratch;\n    public int Other() { scratch = 2; return scratch; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1450");
        assert_eq!(flagged.len(), 2);
    }
}
