use super::support::has_explicit_interface_specifier;
use crate::CsLanguage;
use crate::cst::{is_pascal_case, issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S100 — methods and properties are `PascalCase`. Interior
/// underscores are an explicit Sonar exception; leading/trailing ones are not.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind != "method_declaration" && kind != "property_declaration" {
            return;
        }
        if has_explicit_interface_specifier(node) {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let name_text = node_text(name, source);
        if is_pascal_case(name_text)
            || (name_text.contains('_') && !name_text.starts_with('_') && !name_text.ends_with('_'))
        {
            return;
        }
        let subject = if kind == "method_declaration" {
            "method"
        } else {
            "property"
        };
        issues.push(issue(
            language,
            "S100",
            format!(
                "Rename {subject} '{name_text}' to match pascal case naming rules, consider using '{}'.",
                pascal_suggestion(name_text)
            ),
            range_of(name, source),
        ));
    });
    issues
}

fn pascal_suggestion(name: &str) -> String {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    first.to_uppercase().chain(characters).collect()
}
