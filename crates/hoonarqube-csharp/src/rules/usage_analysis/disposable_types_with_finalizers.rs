use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4002 — finalizers on `IDisposable` types fight the dispose
/// pattern.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node)
            || !base_simple_names(class_node, source).contains(&"IDisposable")
        {
            continue;
        }
        for destructor in collect_kinds(class_node, &["destructor_declaration"]) {
            if is_error_tainted(destructor) {
                continue;
            }
            issues.push(issue(
                language,
                "S4002",
                "Remove this finalizer or implement the dispose pattern correctly.",
                range_of(name_anchor(destructor)),
            ));
        }
    }
    issues
}
