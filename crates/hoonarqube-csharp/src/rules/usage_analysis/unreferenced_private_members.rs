use super::support::{member_uses, member_writes};
use crate::CsLanguage;
use crate::cst::{ancestors_of, issue, modifiers_of, range_of};
use crate::rules::naming::has_explicit_interface_specifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, has_contract_modifier, is_private_member, owner_is_partial,
};
use hoonarqube_ir::Issue;

/// csharpsquid:S4487 — private members nobody references are dead weight.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if !is_private_member(member.declaration, source, member.nested_type)
            || has_contract_modifier(&modifiers)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.flavor != MemberFlavor::Field
            || member.name == "Main"
            || (member.flavor == MemberFlavor::Method
                && has_explicit_interface_specifier(member.declaration))
        {
            continue;
        }
        let writes = member_writes(symbols, member, source);
        if !member.has_initializer && writes.is_empty() {
            continue;
        }
        if member_uses(symbols, member, source)
            .into_iter()
            .any(|usage| {
                !writes.iter().any(|write| {
                    write.id() == usage.id()
                        || ancestors_of(usage).any(|ancestor| ancestor.id() == write.id())
                })
            })
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4487",
            format!(
                "Remove this unread private field '{}' or refactor the code to use its value.",
                member.name,
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
    fn s4487_minimal_class_produces_no_findings() {
        let report = analyze_default("class A\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s4487_reports_initialized_unread_fields_only() {
        let report = analyze_default(
            "class A\n{\n    private int Stale = 1;\n    private bool Gone { get; set; }\n    public int Live;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4487");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(
            flagged[0].message,
            "Remove this unread private field 'Stale' or refactor the code to use its value."
        );
    }

    #[test]
    fn s4487_reports_fields_only_written_in_constructor() {
        let report = analyze_default(
            "public class Archive\n{\n    private int stale;\n    private bool gone;\n\n    public Archive()\n    {\n        stale = 1;\n        gone = false;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4487");
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s4487_ignores_entry_point_named_main() {
        let report = analyze_default("class A\n{\n    private void Main(string[] args) { }\n}\n");
        assert!(with_key(&report, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s4487_ignores_contract_modifier_members() {
        let report = analyze_default("class A\n{\n    private virtual void Hook() { }\n}\n");
        assert!(with_key(&report, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s4487_ignores_private_methods_invoked_inside_the_class() {
        let report = analyze_default(
            "class A\n{\n    private int Compute() => 1;\n    public int Run() { return Compute(); }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s4487_does_not_borrow_reads_from_unrelated_types() {
        let report = analyze_default(
            "class A\n{\n    private int stale = 1;\n}\n\nclass B\n{\n    private int stale;\n    public int Read() => stale;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4487");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }
}
