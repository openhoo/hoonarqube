use crate::cst::{issue, matches_logger_format, node_text, range_of, simple_name, walk_all};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6669 — logger-typed fields and properties follow the
/// configured naming format.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const LOGGER_TYPE_TAILS: [&str; 2] = ["Logger", "ILogger"];
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind != "field_declaration" && kind != "property_declaration" {
            return;
        }
        let declared_type = if kind == "property_declaration" {
            node.child_by_field_name("type")
        } else {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|declaration| declaration.child_by_field_name("type"))
        };
        let Some(declared_type) = declared_type else {
            return;
        };
        if !LOGGER_TYPE_TAILS.contains(&simple_name(node_text(declared_type, source))) {
            return;
        }
        let member_names: Vec<Node> = if kind == "property_declaration" {
            node.child_by_field_name("name").into_iter().collect()
        } else {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .filter(|child| child.kind() == "variable_declaration")
                .flat_map(|declaration| {
                    let mut declarator_cursor = declaration.walk();
                    declaration
                        .children(&mut declarator_cursor)
                        .filter(|child| child.kind() == "variable_declarator")
                        .collect::<Vec<Node>>()
                })
                .filter_map(|declarator| declarator.child_by_field_name("name"))
                .collect()
        };
        for name in member_names {
            let name_text = node_text(name, source);
            if matches_logger_format(name_text, &options.logger_name_format) {
                continue;
            }
            issues.push(issue(
                language,
                "S6669",
                format!(
                    "Rename this {} '{name_text}' to match the regular expression '{}'.",
                    if kind == "field_declaration" {
                        "field"
                    } else {
                        "property"
                    },
                    options.logger_name_format
                ),
                range_of(name, source),
            ));
        }
    });
    issues
}
