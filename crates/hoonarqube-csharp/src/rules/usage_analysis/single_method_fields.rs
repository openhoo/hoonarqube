use super::support::member_uses;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, TIER_B_MEMBER_KINDS, UsageSymbols, is_private_member, is_ref_or_out_argument,
    nearest_ancestor_of_kinds, owner_is_partial,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1450 — private instance fields touched by exactly one method
/// behave like locals and belong in that method. `static` and `readonly`
/// fields carry type-level contracts, and reference-escaped uses cannot
/// move, so both stay exempt.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers, "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        // The reference rule converts locals, not type-level state: `static`
        // and `readonly` fields carry contracts no local can express.
        if has_modifier(&modifiers, "static") || has_modifier(&modifiers, "readonly") {
            continue;
        }
        let uses = member_uses(symbols, member, source);
        if uses.is_empty() {
            continue;
        }
        if uses
            .iter()
            .any(|use_site| is_ref_or_out_argument(*use_site, source))
        {
            continue;
        }
        let mut homes: Vec<Option<Node>> = uses
            .iter()
            .map(|use_site| nearest_ancestor_of_kinds(*use_site, &TIER_B_MEMBER_KINDS))
            .collect();
        homes.sort_by_key(|home| home.map(|owner| owner.byte_range().start));
        homes.dedup_by_key(|home| home.map(|owner| owner.byte_range().start));
        let Some(home) = single_method_home(&homes) else {
            continue;
        };
        // The reference rule converts the field only when the method
        // overwrites it before every read; fields read first carry cross-call
        // state that no local variable can hold.
        if !reads_follow_pure_writes(&uses, home, source) {
            continue;
        }
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
    issues
}

/// The one method that owns every use of the field, when it is not a
/// constructor or accessor — the only shape the reference rule converts.
fn single_method_home<'t>(homes: &[Option<Node<'t>>]) -> Option<Node<'t>> {
    match homes {
        [Some(home)] if home.kind() == "method_declaration" => Some(*home),
        _ => None,
    }
}

/// Whether every read of the field inside `home` is preceded, in lexical
/// order, by a statement that only writes the field. Reads from field
/// initializers are invisible to the reference rule, while reads in
/// expression bodies can never be preceded, so both spare the field.
fn reads_follow_pure_writes<'t>(uses: &[Node<'t>], home: Node<'t>, source: &str) -> bool {
    let home_span = home.byte_range();
    let mut shapes: std::collections::HashMap<usize, (bool, bool, usize)> =
        std::collections::HashMap::new();
    for site in uses {
        let Some(pseudo) = pseudo_statement(*site) else {
            continue;
        };
        let span = pseudo.byte_range();
        if span.start < home_span.start || span.end > home_span.end {
            continue;
        }
        let entry = shapes
            .entry(pseudo.id())
            .or_insert((false, false, span.start));
        let write = is_plain_write(*site, source);
        entry.0 |= write;
        entry.1 |= !write;
    }
    uses.iter().all(|site| {
        if is_plain_write(*site, source) {
            return true;
        }
        let Some(pseudo) = pseudo_statement(*site) else {
            return true;
        };
        let read_start = pseudo.byte_range().start;
        shapes
            .values()
            .any(|(has_write, has_read, start)| *has_write && !*has_read && *start < read_start)
    })
}

/// Whether the site is the left side of a plain `=` assignment, the only
/// shape the reference rule counts as an overwrite.
fn is_plain_write(site: Node<'_>, source: &str) -> bool {
    site.parent().is_some_and(|assignment| {
        assignment.kind() == "assignment_expression"
            && assignment
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == site.id())
            && assignment
                .child_by_field_name("operator")
                .is_some_and(|operator| node_text(operator, source) == "=")
    })
}

/// Nearest statement or expression-body owning a site's execution step.
fn pseudo_statement(node: Node<'_>) -> Option<Node<'_>> {
    std::iter::successors(node.parent(), Node::parent).find(|ancestor| {
        ancestor.kind().ends_with("_statement") || ancestor.kind() == "arrow_expression_clause"
    })
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
