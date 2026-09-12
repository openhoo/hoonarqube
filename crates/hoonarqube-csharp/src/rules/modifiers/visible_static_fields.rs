use super::support::accessibility_rank;
use super::support::field_declarators;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2223 — visible non-constant static fields hide shared
/// mutable state; `readonly` does not rescue them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
            && !has_modifier(&modifiers, "readonly")
            && accessibility_rank(&modifiers) >= 3
        {
            for declarator in field_declarators(field) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                let name_text = node_text(name, source);
                issues.push(issue(
                    language,
                    "S2223",
                    format!(
                        "Change the visibility of '{name_text}' or make it 'const' or 'readonly'."
                    ),
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2223_private_static_fields_are_not_reported() {
        let report = analyze_default(
            "public class C\n{\n    private static int hidden;\n    private protected static int bounded;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2223");
        assert_eq!(flagged.len(), 0);
    }

    #[test]
    fn s2223_externally_visible_static_fields_are_still_reported() {
        let report = analyze_default(
            "public class C\n{\n    public static int shared;\n    internal static int tally;\n    protected internal static int bridged;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2223");
        assert_eq!(flagged.len(), 3);
        let mut spots: Vec<_> = flagged
            .iter()
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        spots.sort_unstable();
        assert_eq!(spots, vec![(3, 22), (4, 24), (5, 34)]);
        assert_eq!(
            flagged[0].message,
            "Change the visibility of 'shared' or make it 'const' or 'readonly'."
        );
    }

    #[test]
    fn s2223_const_and_readonly_static_fields_remain_exempt() {
        let report = analyze_default(
            "public class C\n{\n    public const double Pi = 3.14;\n    public static readonly string Greeting = \"hi\";\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2223");
        assert_eq!(flagged.len(), 0);
    }
}
