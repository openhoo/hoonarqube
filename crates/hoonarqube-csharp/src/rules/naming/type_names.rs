use super::support::TYPE_DECLARATION_KINDS;
use super::support::declaration_kind_word;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_pascal_case, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S101 — types are `PascalCase` without underscores.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NAMING_PATTERN: &str = "'^([A-Z][a-z0-9]+)+([a-z0-9]+)?(_)?$'";
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        if is_pascal_case(name_text) {
            continue;
        }
        issues.push(issue(
            language,
            "S101",
            format!(
                "Rename this {} to match the regular expression {NAMING_PATTERN}.",
                declaration_kind_word(type_node.kind())
            ),
            range_of(name),
        ));
    }
    issues
}
