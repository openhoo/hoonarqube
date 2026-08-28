use crate::CsLanguage;
use crate::cst::{issue, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1659 — one variable declaration per line.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "variable_declaration" {
            return;
        }
        let mut declarators_per_row: std::collections::BTreeMap<usize, Vec<Node>> =
            std::collections::BTreeMap::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                declarators_per_row
                    .entry(child.start_position().row)
                    .or_default()
                    .push(child);
            }
        }
        for row_declarators in declarators_per_row.values() {
            for declarator in row_declarators.iter().skip(1) {
                let name = declarator
                    .child_by_field_name("name")
                    .unwrap_or(*declarator);
                issues.push(issue(
                    language,
                    "S1659",
                    format!(
                        "Declare '{}' in a separate statement.",
                        crate::cst::node_text(name, source)
                    ),
                    range_of(name, source),
                ));
            }
        }
    });
    issues
}
