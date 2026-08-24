use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2166 — classes named `...Exception` must actually derive
/// from an exception type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let name = class_declaration
            .child_by_field_name("name")
            .map_or("", |name| node_text(name, source));
        let derives_exception = base_simple_names(class_declaration, source)
            .iter()
            .any(|base| base.ends_with("Exception"));
        if name.ends_with("Exception") && !derives_exception {
            issues.push(issue(
                language,
                "S2166",
                "Derive this exception-named class from an 'Exception' type.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}
