use super::support::has_explicit_interface_specifier;
use crate::CsLanguage;
use crate::cst::{is_pascal_case, issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S100 — methods and properties are `PascalCase` without
/// underscores.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NAMING_PATTERN: &str = "'^([A-Z][a-z0-9]+)+([a-z0-9]+)?(_)?$'";
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
        if is_pascal_case(name_text) {
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
            format!("Rename this {subject} to match the regular expression {NAMING_PATTERN}."),
            range_of(name),
        ));
    });
    issues
}
