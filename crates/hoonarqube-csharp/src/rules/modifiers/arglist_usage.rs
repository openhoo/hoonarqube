use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4061 — `params` replaced `__arglist` long ago.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if node_text(method, source).contains("__arglist") {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4061",
                "Use the 'params' keyword instead of '__arglist'.",
                range_of(name, source),
            ));
        }
    }
    issues
}
