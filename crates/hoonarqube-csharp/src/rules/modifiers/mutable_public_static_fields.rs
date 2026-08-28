use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2386 — public static mutable fields invite races; only
/// `readonly` (or a property) settles them down.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "readonly")
            && !has_modifier(&modifiers, "const")
        {
            let is_mutable = collect_kinds(field, &["variable_declaration"])
                .into_iter()
                .filter_map(|declaration| declaration.child_by_field_name("type"))
                .any(|field_type| {
                    field_type.kind() == "array_type"
                        || matches!(
                            simple_name(node_text(field_type, source))
                                .split('<')
                                .next()
                                .unwrap_or(""),
                            "List"
                                | "Dictionary"
                                | "HashSet"
                                | "Collection"
                                | "IList"
                                | "IDictionary"
                                | "ICollection"
                        )
                });
            if !is_mutable {
                continue;
            }
            let type_anchor = collect_kinds(field, &["variable_declaration"])
                .into_iter()
                .find_map(|declaration| declaration.child_by_field_name("type"));
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                issues.push(issue(
                    language,
                    "S2386",
                    format!(
                        "Use an immutable collection or reduce the accessibility of the public static field '{}'.",
                        node_text(name, source)
                    ),
                    range_of(type_anchor.unwrap_or(name), source),
                ));
            }
        }
    }
    issues
}
