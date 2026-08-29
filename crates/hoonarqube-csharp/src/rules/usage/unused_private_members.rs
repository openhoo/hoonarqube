use super::support::PrivateMember;
use super::support::count_word_occurrences;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::modifiers::{accessibility_rank, has_modifier, type_declared_rank};
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1144 — unused private types and members are dead weight.
/// Overloads sharing one name must all be unreferenced before the name dies;
/// partial types span files and stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let members = private_member_candidates(root, source);
    let mut declared: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for member in &members {
        *declared.entry(&member.name).or_insert(0) += 1;
    }
    for member in &members {
        if count_word_occurrences(source, &member.name) <= declared[member.name.as_str()] {
            issues.push(issue(
                language,
                "S1144",
                format!(
                    "Remove the unused private {} '{}'.",
                    member.kind_word, member.name
                ),
                range_of(member.anchor, source),
            ));
        }
    }
    // Nested types default to private; partial ones span files.
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mods = modifiers_of(type_node, source);
        if has_modifier(&mods, "partial") || type_declared_rank(type_node, source) != 1 {
            continue;
        }
        let Some(name_node) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        if count_word_occurrences(source, name) <= 1 {
            issues.push(issue(
                language,
                "S1144",
                format!("Remove this unused private {name}."),
                range_of(name_node, source),
            ));
        }
    }
    issues
}

/// Collects private methods, properties, fields, and events declared by
/// non-partial types. Constants are exempt (they often document intent),
/// attributed members may be reflection hooks, and `Main` is an entry point.
fn private_member_candidates<'t>(root: Node<'t>, source: &str) -> Vec<PrivateMember<'t>> {
    let mut candidates = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if has_modifier(&modifiers_of(type_node, source), "partial") {
            continue;
        }
        for member in type_members(type_node) {
            match member.kind() {
                "method_declaration" | "property_declaration" => {
                    if let Some(candidate) = private_named_member(member, source) {
                        candidates.push(candidate);
                    }
                }
                "field_declaration" if is_private_field_like(member, source, true) => {
                    candidates.extend(private_declarators(member, source, "field"));
                }
                "event_field_declaration" if is_private_field_like(member, source, false) => {
                    candidates.extend(private_declarators(member, source, "event"));
                }
                _ => {}
            }
        }
    }
    candidates
}

fn private_named_member<'t>(member: Node<'t>, source: &str) -> Option<PrivateMember<'t>> {
    let name_node = member.child_by_field_name("name")?;
    if accessibility_rank(&modifiers_of(member, source)) != 1
        || !attributes_of(member, source).is_empty()
        || node_text(name_node, source) == "Main"
    {
        return None;
    }
    Some(PrivateMember {
        anchor: name_node,
        name: node_text(name_node, source).to_string(),
        kind_word: if member.kind() == "method_declaration" {
            "method"
        } else {
            "property"
        },
    })
}

fn is_private_field_like(member: Node<'_>, source: &str, exclude_constants: bool) -> bool {
    accessibility_rank(&modifiers_of(member, source)) == 1
        && attributes_of(member, source).is_empty()
        && (!exclude_constants || !has_modifier(&modifiers_of(member, source), "const"))
}

/// Declarator candidates of a field-like declaration.
fn private_declarators<'t>(
    declaration: Node<'t>,
    source: &str,
    kind_word: &'static str,
) -> Vec<PrivateMember<'t>> {
    collect_kinds(declaration, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| {
            let name_node = declarator.child_by_field_name("name")?;
            Some(PrivateMember {
                anchor: declaration,
                name: node_text(name_node, source).to_string(),
                kind_word,
            })
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1144_flags_dead_private_properties_events_and_nested_types() {
        let report = analyze_default(
            "class C\n{\n    int Score => 1;\n    event System.EventHandler Done;\n    class Helper\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1144");
        assert_eq!(flagged.len(), 3);
        assert!(
            flagged
                .iter()
                .any(|issue| issue.message.contains("property"))
        );
        assert!(flagged.iter().any(|issue| issue.message.contains("event")));
        assert!(
            flagged
                .iter()
                .any(|issue| issue.message.contains("private Helper"))
        );
    }

    #[test]
    fn s1144_spares_attributed_members_and_entry_points() {
        let report = analyze_default(
            "class C\n{\n    [System.Obsolete]\n    void Legacy()\n    {\n    }\n\n    static void Main()\n    {\n    }\n\n    [System.ThreadStatic]\n    static int slot;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1144").is_empty());
    }

    #[test]
    fn s1144_keeps_all_overloads_until_the_last_reference_dies() {
        let report = analyze_default(
            "class C\n{\n    void Twice()\n    {\n    }\n\n    void Twice(int n)\n    {\n    }\n\n    static void Main()\n    {\n        Twice(3);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1144").is_empty());
    }

    #[test]
    fn s1144_keeps_callees_reached_from_dead_callers() {
        let report = analyze_default(
            "class C\n{\n    void Dead()\n    {\n        Helper();\n    }\n\n    void Helper()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1144");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("method"));
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s1144_ignores_non_private_visibility() {
        let report = analyze_default(
            "class C\n{\n    internal void Gone()\n    {\n    }\n\n    public int Exposed => 1;\n\n    protected bool flag;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1144").is_empty());
    }

    #[test]
    fn s1144_spares_used_and_public_nested_types() {
        let used = analyze_default(
            "class C\n{\n    class Inner\n    {\n    }\n\n    static void Main()\n    {\n        var item = new Inner();\n    }\n}\n",
        );
        assert!(with_key(&used, "csharpsquid:S1144").is_empty());

        let public_nested = analyze_default("class C\n{\n    public class Open\n    {\n    }\n}\n");
        assert!(with_key(&public_nested, "csharpsquid:S1144").is_empty());
    }
}
