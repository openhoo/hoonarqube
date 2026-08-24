use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of, walk_all};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3872 — parameter names do not duplicate their method's name
/// (case-insensitively).
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "method_declaration" {
            return;
        }
        let Some(method_name) = node.child_by_field_name("name") else {
            return;
        };
        let method_name = node_text(method_name, source);
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters
            .children(&mut parameter_cursor)
            .filter(|child| child.kind() == "parameter")
        {
            let Some(parameter_name) = parameter.child_by_field_name("name") else {
                continue;
            };
            let parameter_text = node_text(parameter_name, source);
            if parameter_text.eq_ignore_ascii_case(method_name) {
                issues.push(issue(
                    language,
                    "S3872",
                    "Rename this parameter; it duplicates the name of its method.",
                    range_of(parameter_name),
                ));
            }
        }
    });
    issues
}
