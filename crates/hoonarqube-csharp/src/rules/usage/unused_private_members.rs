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
                format!("Remove this unused private {}.", member.kind_word),
                range_of(member.anchor),
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
                range_of(name_node),
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
                    let Some(name_node) = member.child_by_field_name("name") else {
                        continue;
                    };
                    if accessibility_rank(&modifiers_of(member, source)) != 1
                        || !attributes_of(member, source).is_empty()
                        || node_text(name_node, source) == "Main"
                    {
                        continue;
                    }
                    candidates.push(PrivateMember {
                        anchor: name_node,
                        name: node_text(name_node, source).to_string(),
                        kind_word: if member.kind() == "method_declaration" {
                            "method"
                        } else {
                            "property"
                        },
                    });
                }
                "field_declaration" => {
                    if accessibility_rank(&modifiers_of(member, source)) == 1
                        && !has_modifier(&modifiers_of(member, source), "const")
                        && attributes_of(member, source).is_empty()
                    {
                        candidates.extend(private_declarators(member, source, "field"));
                    }
                }
                "event_field_declaration"
                    if accessibility_rank(&modifiers_of(member, source)) == 1
                        && attributes_of(member, source).is_empty() =>
                {
                    candidates.extend(private_declarators(member, source, "event"));
                }
                _ => {}
            }
        }
    }
    candidates
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
                anchor: name_node,
                name: node_text(name_node, source).to_string(),
                kind_word,
            })
        })
        .collect()
}
